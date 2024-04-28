use anyhow::Result;
use axum::{
    extract::{Path, State}, http::StatusCode, response::{Html, IntoResponse}, routing::get, Router
};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tower_http::services::ServeDir;
use tracing::{info, warn};

#[derive(Debug)]
struct HttpServeState {
    path: PathBuf,
}

pub async fn process_http_serve(path: PathBuf, port: u16) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Serving {:?} on {}", path, addr);

    let state = HttpServeState { path: path.clone() };
    // axum router
    let router = Router::new()
        .nest_service("/tower", ServeDir::new(path))
        .route("/*path", get(file_handler))
        .with_state(Arc::new(state));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;
    Ok(())
}

fn is_dir(path: &std::path::Path) -> bool {
    match std::fs::metadata(path) {
        Ok(metadata) => metadata.is_dir(),
        Err(_) => false,
    }
}

fn remove_dir(path: String, dir: String) -> String {
    if path.starts_with(&dir) {
        // 如果字符串以指定前缀开头，则通过切片去除前缀
        path[dir.len()..].to_owned()
    } else {
        // 如果字符串不以指定前缀开头，则返回原始字符串
        path
    }
}

async fn file_handler(
    State(state): State<Arc<HttpServeState>>,
    Path(path): Path<String>,
) -> (StatusCode, impl IntoResponse) {
    let p = std::path::Path::new(&state.path).join(path);
    info!("Reading file {:?}", p);
    if !p.exists() {
        (
            StatusCode::NOT_FOUND,
            format!("File {} note found", p.display()).into_response(),
        )
    } else {
        if is_dir(&p) {
            let mut entries = tokio::fs::read_dir(p).await.unwrap();
            let mut content = "".to_string();
            while let Some(entry) = entries.next_entry().await.unwrap() {
                let path = entry.path();
                content.push_str(&format!(
                    "<li><a href=\"\\{}\">{}</a></li>\n",
                    remove_dir(path.display().to_string(), state.path.display().to_string()),
                    path.file_name().unwrap().to_str().unwrap().to_owned(),
                ));
            }

            //content = format!("<html><body><ul>{}</ul></body></html>", content);
            content = format!(
                r#"
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>http server</title>
</head>
<body>
<ul>{}</ul>
</body>
</html>"#,
                content
            );
            (StatusCode::OK, Html(content).into_response())
        } else {
            match tokio::fs::read_to_string(p).await {
                Ok(content) => {
                    info!("Read {} bytes", content.len());
                    (StatusCode::OK, content.into_response())
                }
                Err(e) => {
                    warn!("Error reading file: {:?}", e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        e.to_string().into_response(),
                    )
                }
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_file_handler() {
        let state = Arc::new(HttpServeState {
            path: PathBuf::from("."),
        });
        let (status, content) = file_handler(State(state), Path("Cargo.toml".to_string())).await;
        assert_eq!(status, StatusCode::OK);
        assert!(content.trim().starts_with("[package]"));
    }
}
