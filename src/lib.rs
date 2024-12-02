#[allow(warnings)]
mod bindings;

use querystring;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::ops::{Add, DerefMut};
use std::time::{Duration, SystemTime};

use bindings::{
    exports::supabase::wrappers::routines::Guest,
    supabase::wrappers::{
        http, stats, time,
        types::{Cell, Context, FdwError, FdwResult, OptionsType, Row, TypeOid},
        utils,
    },
};

static FDW_NAME: &str = "MSGraphFDW";

#[derive(Debug, Default)]
struct MSGraphCredentials {
    client_id: String,
    client_secret: String,
    tenant_id: String,
}

#[derive(Debug, Default)]
struct MSGraphFDW {
    graph_base_url: String,
    token_base_url: String,
    credentials: MSGraphCredentials,
    access_token: Option<MSGraphAccessToken>,
    current_page: Option<ODataResponsePage>,
    page_offset: usize,
}

// pointer for the static FDW instance
static mut INSTANCE: *mut MSGraphFDW = std::ptr::null_mut::<MSGraphFDW>();

impl MSGraphFDW {
    // initialise FDW instance
    fn init_instance() {
        let instance = Self::default();
        unsafe {
            INSTANCE = Box::leak(Box::new(instance));
        }
    }

    fn this_mut() -> &'static mut Self {
        unsafe { &mut (*INSTANCE) }
    }

    fn acquire_access_token(&mut self) -> Result<MSGraphAccessToken, FdwError> {
        let token_req = EntraIDTokenRequest {
            client_id: self.credentials.client_id.clone(),
            client_secret: self.credentials.client_secret.clone(),
            scope: "https://graph.microsoft.com/.default".to_owned(),
            grant_type: "client_credentials".to_owned(),
        };

        let token_http_req = http::Request {
            method: http::Method::Post,
            url: format!(
                "{}/{}/oauth2/v2.0/token",
                self.token_base_url, self.credentials.tenant_id
            ),
            headers: vec![(
                "Content-Type".to_owned(),
                "application/x-www-form-urlencoded".to_owned(),
            )],
            body: serde_urlencoded::to_string(&token_req).unwrap(),
        };

        utils::report_info(&format!("Requesting token: {}", token_http_req.url));

        let token_resp = http::post(&token_http_req)?;
        let token_resp_json: EntraIDTokenResponse =
            serde_json::from_str(&token_resp.body).map_err(|e| e.to_string())?;

        self.access_token = Some(MSGraphAccessToken {
            access_token: token_resp_json.access_token,
            expires_at: SystemTime::now().add(Duration::new(token_resp_json.expires_in, 0)),
        });

        Ok(self.access_token.as_ref().unwrap().clone())
    }
}

impl Guest for MSGraphFDW {
    fn host_version_requirement() -> String {
        // semver expression for Wasm FDW host version requirement
        // ref: https://docs.rs/semver/latest/semver/enum.Op.html
        "^0.1.3".to_string()
    }

    fn init(ctx: &Context) -> FdwResult {
        Self::init_instance();
        let this = Self::this_mut();

        let opts = ctx.get_options(OptionsType::Server);
        this.graph_base_url = opts.require_or("graph_base_url", "https://graph.microsoft.com/v1.0");
        this.token_base_url =
            opts.require_or("token_base_url", "https://login.microsoftonline.com");

        let tenant_id = opts.require("tenant_id")?;
        this.credentials.tenant_id = utils::get_vault_secret(&tenant_id).unwrap_or_default();

        let client_id = opts.require("client_id")?;
        this.credentials.client_id = utils::get_vault_secret(&client_id).unwrap_or_default();

        let client_secret = opts.require("client_secret")?;
        this.credentials.client_secret =
            utils::get_vault_secret(&client_secret).unwrap_or_default();

        Ok(())
    }

    fn begin_scan(ctx: &Context) -> FdwResult {
        let this = Self::this_mut();

        let current_token = this.acquire_access_token()?;

        let opts = ctx.get_options(OptionsType::Table);
        let object = opts.require("object")?;
        let url = format!(
            "{}/{}?{}",
            this.graph_base_url,
            object,
            querystring::stringify(vec![
                (
                    "$select",
                    "id,employeeId,userPrincipalName,givenName,surname,mail,mobilePhone"
                ),
                ("$filter", "userType ne 'guest' and accountEnabled eq true"),
                ("$orderby", "userPrincipalName"),
                ("$count", "true"),
                ("$top", "250")
            ])
        );

        utils::report_info(&format!("Querying: {}", url));

        let headers: Vec<(String, String)> = vec![
            ("Authorization".to_owned(), current_token.header()),
            ("ConsistencyLevel".to_owned(), "eventual".to_owned()),
        ];

        let req = http::Request {
            method: http::Method::Get,
            url,
            headers,
            body: String::default(),
        };

        let resp = http::get(&req)?;

        let initial_page: ODataResponsePage =
            serde_json::from_str(&resp.body).map_err(|e| e.to_string())?;
        this.current_page = Some(initial_page.clone());

        utils::report_info(&format!(
            "We found {} matching records",
            initial_page.total_count.unwrap_or_default()
        ));

        stats::inc_stats(FDW_NAME, stats::Metric::CreateTimes, 1);

        Ok(())
    }

    fn iter_scan(ctx: &Context, row: &Row) -> Result<Option<u32>, FdwError> {
        let this = Self::this_mut();

        let mut current_page = this.current_page.as_mut().unwrap();

        if this.page_offset >= current_page.items.len() && !current_page.has_next() {
            return Ok(None);
        }

        if this.page_offset >= current_page.items.len() && current_page.has_next() {
            this.current_page = Some(
                current_page
                    .clone()
                    .fetch_next(this.access_token.as_ref().unwrap().access_token.clone())
                    .map_err(|e| e.to_string())?,
            );

            current_page = this.current_page.as_mut().unwrap();
        }

        let src_row = current_page.items[this.page_offset].clone();

        for tgt_col in ctx.get_columns() {
            let tgt_col_name = tgt_col.name();
            let src = src_row
                .as_object()
                .and_then(|v| v.get(&tgt_col_name))
                .ok_or(format!("source column '{}' not found", tgt_col_name))?;
            let cell = match tgt_col.type_oid() {
                TypeOid::Bool => src.as_bool().map(Cell::Bool),
                TypeOid::String => src.as_str().map(|v| Cell::String(v.to_owned())),
                TypeOid::Timestamp => {
                    if let Some(s) = src.as_str() {
                        let ts = time::parse_from_rfc3339(s)?;
                        Some(Cell::Timestamp(ts))
                    } else {
                        None
                    }
                }
                TypeOid::Json => src.as_object().map(|_| Cell::Json(src.to_string())),
                _ => {
                    return Err(format!(
                        "column {} data type is not supported",
                        tgt_col_name
                    ));
                }
            };

            row.push(cell.as_ref());
        }

        this.page_offset += 1;

        Ok(Some(0))
    }

    fn re_scan(_ctx: &Context) -> FdwResult {
        Err("re_scan on foreign table is not supported".to_owned())
    }

    fn end_scan(_ctx: &Context) -> FdwResult {
        let this = Self::this_mut();
        this.current_page = None;
        this.page_offset = 0;
        Ok(())
    }

    fn begin_modify(_ctx: &Context) -> FdwResult {
        Err("modify on foreign table is not supported".to_owned())
    }

    fn insert(_ctx: &Context, _row: &Row) -> FdwResult {
        Ok(())
    }

    fn update(_ctx: &Context, _rowid: Cell, _row: &Row) -> FdwResult {
        Ok(())
    }

    fn delete(_ctx: &Context, _rowid: Cell) -> FdwResult {
        Ok(())
    }

    fn end_modify(_ctx: &Context) -> FdwResult {
        Ok(())
    }
}

#[derive(Serialize, Debug)]
struct EntraIDTokenRequest {
    client_id: String,
    client_secret: String,
    scope: String,
    grant_type: String,
}

#[derive(Deserialize, Debug)]
struct EntraIDTokenResponse {
    access_token: String,
    expires_in: u64,
}

#[derive(Debug, Clone)]
struct MSGraphAccessToken {
    access_token: String,
    expires_at: SystemTime,
}

impl MSGraphAccessToken {
    fn is_about_to_expire(&self) -> bool {
        self.expires_at <= SystemTime::now().add(Duration::from_secs(60))
    }

    fn header(&self) -> String {
        format!("Bearer {}", self.access_token)
    }
}

#[derive(Debug, Clone, Deserialize)]
struct ODataResponsePage {
    #[serde(rename = "@odata.count")]
    total_count: Option<u64>,
    #[serde(rename = "@odata.nextLink")]
    next_page: Option<String>,
    #[serde(rename = "value")]
    items: Vec<JsonValue>,
}

impl ODataResponsePage {
    fn has_next(&self) -> bool {
        self.next_page.is_some()
    }

    fn fetch_next(self, access_token: String) -> Result<ODataResponsePage, FdwError> {
        let next_page_url = self.next_page.as_ref().ok_or("No next page")?;
        let headers: Vec<(String, String)> = vec![
            ("Authorization".to_owned(), access_token),
            ("ConsistencyLevel".to_owned(), "eventual".to_owned()),
        ];

        let req = http::Request {
            method: http::Method::Get,
            url: next_page_url.to_owned(),
            headers,
            body: String::default(),
        };
        let resp = http::get(&req)?;

        serde_json::from_str(&resp.body).map_err(|e| e.to_string())?
    }
}

bindings::export!(MSGraphFDW with_types_in bindings);
