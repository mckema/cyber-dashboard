//! Wiki.js 2.5 assets: upload a file (REST `POST /u`, multipart) into the job's
//! asset folder and check it reads back. Used for the FR-A4 month-to-date report
//! PDF linked from the dashboard page.
//!
//! How Wiki.js 2.5.317 handles it (server/controllers/upload.js, models/assets.js):
//! - `/u` takes the API key as `Authorization: Bearer`. It needs global write:assets
//!   and a page rule granting write:assets on `<folder>/<file>`; that check passes
//!   no locale, so only a rule with `locales: []` matches (bootstrap sets it).
//! - Body: two multipart parts both named `mediaUpload`, first `{"folderId":N}`,
//!   then exactly one file. The server lowercases and sanitises the file name; a
//!   file of the same name in the folder is overwritten in place (no history).
//! - It answers `ok` even when saving failed (the error is only logged), so the
//!   file is fetched back from `/<folder>/<file>` and compared.
//! - Limit 5 MB (uploads.maxFileSize default); served with
//!   `Content-Disposition: attachment` (uploads.forceDownload default).

use reqwest::blocking::Client;
use reqwest::blocking::multipart::{Form, Part};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{SIGNIN, bot_auth, bot_base, err_chain, gql_bot_with, head, is_signin};
use crate::feeds::common::{self, Fatal};

/// Default asset folder the job writes to (created by bootstrap); WIKI_ASSET_FOLDER overrides it.
pub const DEFAULT_ASSET_FOLDER: &str = "exploit-watch";
/// File name of the month-to-date report PDF.
pub const MTD_REPORT_NAME: &str = "cyber-threat-report-to-date.pdf";
/// Wiki.js uploads.maxFileSize default (5 MiB); larger uploads are cut off by multer.
pub const MAX_ASSET_BYTES: usize = 5 * 1024 * 1024;

/// The top-level asset folder the job uploads into, served as /<folder>/<file>:
/// WIKI_ASSET_FOLDER, or DEFAULT_ASSET_FOLDER when unset or blank. Every asset
/// path, link and bootstrap rule takes the folder from here.
pub fn asset_folder() -> Result<String, Fatal> {
    asset_folder_from(&|k| std::env::var(k).ok())
}

/// asset_folder with an explicit variable lookup (tests, callers with their own lookup).
/// Fatal for a value Wiki.js would not keep as the folder slug (only a-z 0-9 - _,
/// starting with a letter or digit, no `/`: one top-level folder).
pub fn asset_folder_from(get: &dyn Fn(&str) -> Option<String>) -> Result<String, Fatal> {
    let f = get("WIKI_ASSET_FOLDER").map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let Some(f) = f else {
        return Ok(DEFAULT_ASSET_FOLDER.into());
    };
    let ok = f.chars().next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && f.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_'));
    if !ok {
        return Err(Fatal(format!(
            "WIKI_ASSET_FOLDER={f:?}: use one top-level folder name of a-z 0-9 - _ (starting with a letter or digit)"
        )));
    }
    Ok(f)
}

/// Top-level asset folders (`parentFolderId: 0`). Needs read:assets plus a page
/// rule matching the folder slug itself (path "<folder>", no locale).
pub(crate) const FOLDERS: &str = "query ($p: Int!) { assets { folders(parentFolderId: $p) { id slug } } }";

/// Id of the top-level folder `slug` in an `assets.folders` reply.
pub(crate) fn folder_id(data: &Value, slug: &str) -> Option<i64> {
    data["assets"]["folders"].as_array()?.iter().find(|f| f["slug"] == slug).and_then(|f| f["id"].as_i64())
}

/// Upload `bytes` as /<asset_folder()>/`name` (replacing a file of that name) with
/// the bot key, then fetch it back and compare. Returns the asset path
/// ("/exploit-watch/…" by default). One IAP token (iap::token()) serves the folder
/// lookup, the upload and the read-back.
pub fn upload_asset(name: &str, bytes: &[u8]) -> Result<String, Fatal> {
    let key = std::env::var("WIKIJS_API_KEY").unwrap_or_default();
    let folder = asset_folder()?;
    let iap = super::iap::token()?;
    upload_asset_with(common::client(), &bot_base(), &key, &iap, &folder, name, bytes)
}

fn short_sha(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))[..12].to_string()
}

/// upload_asset with explicit inputs (tests, or callers with their own client).
pub fn upload_asset_with(client: &Client, base: &str, key: &str, iap: &str, folder: &str, name: &str, bytes: &[u8])
    -> Result<String, Fatal> {
    // Wiki.js stores the name lowercased and sanitised; keep to names it stores as is,
    // so the read-back URL and the returned link are the file's real path.
    let name = name.to_lowercase();
    let ok_name = name.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
    if !ok_name {
        return Err(Fatal(format!("wiki asset name {name:?}: use only a-z 0-9 . - _ (starting with a letter or digit)")));
    }
    let path = format!("/{folder}/{name}");
    if bytes.len() > MAX_ASSET_BYTES {
        return Err(Fatal(format!(
            "wiki asset {path}: {} bytes is over the Wiki.js upload limit of {MAX_ASSET_BYTES} bytes (uploads.maxFileSize)",
            bytes.len()
        )));
    }
    let base = base.trim_end_matches('/');

    let d = gql_bot_with(client, base, key, iap, FOLDERS, json!({"p": 0}))
        .map_err(|e| Fatal(format!("wiki asset folder lookup: {}", e.0)))?;
    let fid = folder_id(&d, folder).ok_or_else(|| {
        Fatal(format!(
            "wiki asset folder '{folder}' not found, or not visible to the bot key \
             (needs read:assets on '{folder}'): run `bootstrap` with the same WIKI_ASSET_FOLDER"
        ))
    })?;

    let mime = if name.ends_with(".pdf") { "application/pdf" } else { "application/octet-stream" };
    let file = Part::bytes(bytes.to_vec()).file_name(name.clone()).mime_str(mime).expect("valid MIME");
    // Order matters: multer must see the folder part before the file part.
    let form = Form::new().text("mediaUpload", json!({"folderId": fid}).to_string()).part("mediaUpload", file);
    let r = bot_auth(client.post(format!("{base}/u")), key, iap)
        .multipart(form)
        .send()
        .map_err(|e| Fatal(format!("wiki asset upload: cannot reach Wiki.js at {base}: {}", err_chain(&e))))?;
    let status = r.status().as_u16();
    let final_url = r.url().to_string();
    let text = r.text().unwrap_or_default();
    if is_signin(status, &final_url, &text) {
        return Err(Fatal(format!("wiki asset upload: {SIGNIN}")));
    }
    if !(200..300).contains(&status) {
        return Err(Fatal(format!("wiki asset upload {path}: HTTP {status}: {}", head(&text, 300))));
    }

    // Wiki.js replies `ok` even when it failed to save; trust only what reads back.
    let r = bot_auth(client.get(format!("{base}{path}")), key, iap)
        .send()
        .map_err(|e| Fatal(format!("wiki asset read-back: cannot reach Wiki.js at {base}: {}", err_chain(&e))))?;
    let status = r.status().as_u16();
    let final_url = r.url().to_string();
    let got = r.bytes().map_err(|e| Fatal(format!("wiki asset read-back {path}: {}", err_chain(&e))))?;
    if got.as_ref() == bytes {
        return Ok(path);
    }
    let text = String::from_utf8_lossy(&got);
    if is_signin(status, &final_url, &text) {
        return Err(Fatal(format!("wiki asset read-back: {SIGNIN}")));
    }
    if !(200..300).contains(&status) {
        return Err(Fatal(format!("wiki asset read-back {path}: HTTP {status}: {}", head(&text, 300))));
    }
    Err(Fatal(format!(
        "wiki asset: uploaded {path} ({} bytes, sha256 {}) but read back {} bytes (sha256 {}); \
         see `docker compose logs wiki` for the save error",
        bytes.len(),
        short_sha(bytes),
        got.len(),
        short_sha(&got)
    )))
}

#[cfg(test)]
mod tests {
    use super::super::testing::{Canned, canned, client, serve};
    use super::*;

    const FOLDERS_OK: &str = r#"{"data":{"assets":{"folders":[{"id":3,"slug":"other"},{"id":7,"slug":"exploit-watch"}]}}}"#;

    fn upload(replies: Vec<Canned>, iap: &str, name: &str, bytes: &[u8]) -> (Result<String, Fatal>, Vec<String>) {
        let n = replies.len();
        let (base, rx) = serve(replies);
        let r = upload_asset_with(&client(), &format!("{base}/"), "KEY", iap, DEFAULT_ASSET_FOLDER, name, bytes);
        let seen: Vec<String> = rx.try_iter().take(n).collect();
        (r, seen)
    }

    #[test]
    fn upload_ok_sends_multipart_in_order_and_reads_back() {
        let pdf = "%PDF-1.7 fake\n";
        let (r, seen) = upload(vec![canned(200, FOLDERS_OK), canned(200, "ok"), canned(200, pdf)],
                               "IAPTOK", "Cyber-Threat-Report-To-Date.PDF", pdf.as_bytes());
        assert_eq!(r.unwrap(), "/exploit-watch/cyber-threat-report-to-date.pdf");
        assert_eq!(seen.len(), 3);

        let q = seen[0].to_lowercase();
        assert!(q.starts_with("post /graphql "), "{q}");
        assert!(q.contains("folders(parentfolderid: $p)") && q.contains(r#""variables":{"p":0}"#), "{q}");

        let up = &seen[1];
        let low = up.to_lowercase();
        assert!(low.starts_with("post /u "), "{up}");
        assert!(low.contains("authorization: bearer key\r\n"));
        assert!(low.contains("proxy-authorization: bearer iaptok\r\n"));
        assert!(low.contains("content-type: multipart/form-data; boundary="), "{up}");
        let meta = up.find("Content-Disposition: form-data; name=\"mediaUpload\"\r\n\r\n{\"folderId\":7}\r\n")
            .unwrap_or_else(|| panic!("folder part missing: {up}"));
        let file = up.find("Content-Disposition: form-data; name=\"mediaUpload\"; filename=\"cyber-threat-report-to-date.pdf\"")
            .unwrap_or_else(|| panic!("file part missing: {up}"));
        assert!(meta < file, "folder part must come first");
        assert!(up[file..].contains("Content-Type: application/pdf\r\n\r\n%PDF-1.7 fake\n\r\n--"), "{up}");
        assert_eq!(up.matches("name=\"mediaUpload\"").count(), 2);

        let get = seen[2].to_lowercase();
        assert!(get.starts_with("get /exploit-watch/cyber-threat-report-to-date.pdf "), "{get}");
        assert!(get.contains("authorization: bearer key\r\n") && get.contains("proxy-authorization: bearer iaptok\r\n"));
    }

    #[test]
    fn upload_no_iap_header_when_unset() {
        let (r, seen) = upload(vec![canned(200, FOLDERS_OK), canned(200, "ok"), canned(200, "x")], "", "a.pdf", b"x");
        assert_eq!(r.unwrap(), "/exploit-watch/a.pdf");
        assert!(seen.iter().all(|s| !s.to_lowercase().contains("proxy-authorization")));
    }

    #[test]
    fn upload_read_back_mismatch_is_fatal() {
        let (r, _) = upload(vec![canned(200, FOLDERS_OK), canned(200, "ok"), canned(200, "old")], "", "a.pdf", b"new!");
        assert_eq!(
            r.unwrap_err().0,
            format!("wiki asset: uploaded /exploit-watch/a.pdf (4 bytes, sha256 {}) but read back 3 bytes (sha256 {}); \
                     see `docker compose logs wiki` for the save error", short_sha(b"new!"), short_sha(b"old"))
        );
        let (r, _) = upload(vec![canned(200, FOLDERS_OK), canned(200, "ok"), canned(404, "Not Found")], "", "a.pdf", b"x");
        assert_eq!(r.unwrap_err().0, "wiki asset read-back /exploit-watch/a.pdf: HTTP 404: Not Found");
    }

    #[test]
    fn upload_missing_folder_is_clear() {
        let (r, seen) = upload(vec![canned(200, r#"{"data":{"assets":{"folders":[{"id":3,"slug":"other"}]}}}"#)],
                               "", "a.pdf", b"x");
        assert_eq!(
            r.unwrap_err().0,
            "wiki asset folder 'exploit-watch' not found, or not visible to the bot key \
             (needs read:assets on 'exploit-watch'): run `bootstrap` with the same WIKI_ASSET_FOLDER"
        );
        assert_eq!(seen.len(), 1, "nothing uploaded");
        let (r, _) = upload(vec![canned(200, r#"{"data":{"assets":{"folders":null}}}"#)], "", "a.pdf", b"x");
        assert!(r.unwrap_err().0.starts_with("wiki asset folder 'exploit-watch' not found"));
    }

    #[test]
    fn upload_http_error_and_signin() {
        let (r, _) = upload(vec![canned(200, FOLDERS_OK),
                                 canned(403, r#"{"succeeded":false,"message":"You are not authorized to upload files to this folder."}"#)],
                            "", "a.pdf", b"x");
        assert_eq!(r.unwrap_err().0, "wiki asset upload /exploit-watch/a.pdf: HTTP 403: \
            {\"succeeded\":false,\"message\":\"You are not authorized to upload files to this folder.\"}");
        let (r, _) = upload(vec![canned(200, FOLDERS_OK), canned(200, "<html><a href=\"https://accounts.google.com/x\">")],
                            "", "a.pdf", b"x");
        assert_eq!(r.unwrap_err().0, format!("wiki asset upload: {SIGNIN}"));
        let (r, _) = upload(vec![canned(200, r#"{"errors":[{"message":"Forbidden"}]}"#)], "", "a.pdf", b"x");
        assert_eq!(r.unwrap_err().0, "wiki asset folder lookup: GraphQL errors: Forbidden");
    }

    #[test]
    fn upload_refuses_big_or_odd_files_before_sending() {
        let (base, rx) = serve(vec![]);
        let big = vec![0u8; MAX_ASSET_BYTES + 1];
        let e = upload_asset_with(&client(), &base, "KEY", "", DEFAULT_ASSET_FOLDER, MTD_REPORT_NAME, &big).unwrap_err().0;
        assert_eq!(e, format!("wiki asset /exploit-watch/cyber-threat-report-to-date.pdf: {} bytes is over the Wiki.js \
                               upload limit of 5242880 bytes (uploads.maxFileSize)", MAX_ASSET_BYTES + 1));
        for bad in ["", "a b.pdf", "../x.pdf", ".hidden", "x#1.pdf"] {
            let e = upload_asset_with(&client(), &base, "KEY", "", DEFAULT_ASSET_FOLDER, bad, b"x").unwrap_err().0;
            assert!(e.starts_with("wiki asset name "), "{bad}: {e}");
        }
        assert!(rx.try_iter().next().is_none(), "no request sent");
    }

    #[test]
    fn folder_id_lookup() {
        let d: Value = serde_json::from_str(FOLDERS_OK).unwrap();
        let d = &d["data"];
        assert_eq!(folder_id(d, "exploit-watch"), Some(7));
        assert_eq!(folder_id(d, "nope"), None);
        assert_eq!(folder_id(&Value::Null, "exploit-watch"), None);
    }

    #[test]
    fn asset_folder_default_and_override() {
        let folder = |v: Option<&str>| asset_folder_from(&|k| (k == "WIKI_ASSET_FOLDER").then(|| v.map(String::from)).flatten());
        assert_eq!(folder(None).unwrap(), "exploit-watch");
        assert_eq!(folder(Some("  ")).unwrap(), "exploit-watch", "blank is unset");
        assert_eq!(folder(Some(" cyber-threat ")).unwrap(), "cyber-threat");
        assert_eq!(folder(Some("ctp_2026")).unwrap(), "ctp_2026");
        for bad in ["Exploit-Watch", "a/b", "/x", "-x", "x y", "x.pdf", "é"] {
            let e = folder(Some(bad)).unwrap_err().0;
            assert!(e.starts_with(&format!("WIKI_ASSET_FOLDER={bad:?}: ")), "{bad}: {e}");
        }
    }

    #[test]
    fn upload_into_another_folder() {
        let folders = r#"{"data":{"assets":{"folders":[{"id":7,"slug":"exploit-watch"},{"id":9,"slug":"cyber-threat"}]}}}"#;
        let (base, rx) = serve(vec![canned(200, folders), canned(200, "ok"), canned(200, "x")]);
        let r = upload_asset_with(&client(), &base, "KEY", "", "cyber-threat", "a.pdf", b"x");
        assert_eq!(r.unwrap(), "/cyber-threat/a.pdf");
        let seen: Vec<String> = rx.try_iter().collect();
        assert!(seen[1].contains("{\"folderId\":9}"), "{}", seen[1]);
        assert!(seen[2].starts_with("GET /cyber-threat/a.pdf "), "{}", seen[2]);
    }
}
