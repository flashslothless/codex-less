use std::borrow::Cow;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use rmcp::ErrorData as McpError;
use rmcp::ServiceExt;
use rmcp::handler::server::ServerHandler;
use rmcp::model::CallToolRequestParam;
use rmcp::model::CallToolResult;
use rmcp::model::Content;
use rmcp::model::Implementation;
use rmcp::model::InitializeRequestParam;
use rmcp::model::InitializeResult;
use rmcp::model::JsonObject;
use rmcp::model::ListToolsResult;
use rmcp::model::PaginatedRequestParam;
use rmcp::model::ProtocolVersion;
use rmcp::model::ServerCapabilities;
use rmcp::model::ServerInfo;
use rmcp::model::Tool;
use rmcp::service::RequestContext;
use rmcp::service::RoleServer;
use rmcp::service::RunningService;
use rmcp::transport::stdio;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;
use tokio::fs as tokio_fs;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::sync::Notify;
use tokio::sync::RwLock;
use tokio::task;
use tokio::time::timeout;
use uuid::Uuid;

const MAX_FETCH_BODY_BYTES: usize = 64 * 1024;
const DEFAULT_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum ContentEncoding {
    #[default]
    Utf8,
    Base64,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadArgs {
    pub path: String,
    #[serde(default)]
    pub encoding: ContentEncoding,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EditArgs {
    pub path: String,
    pub target: String,
    pub replacement: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct WriteArgs {
    pub path: String,
    pub content: String,
    #[serde(default)]
    pub encoding: ContentEncoding,
    #[serde(default = "WriteArgs::default_create")]
    pub create: bool,
    #[serde(default = "WriteArgs::default_overwrite")]
    pub overwrite: bool,
}

impl WriteArgs {
    const fn default_create() -> bool {
        true
    }

    const fn default_overwrite() -> bool {
        true
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct BashArgs {
    pub command: String,
    pub cwd: Option<String>,
    pub env: Option<HashMap<String, String>>,
    #[serde(default)]
    pub background: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct BashOutputArgs {
    pub session_id: String,
    pub cursor: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct KillShellArgs {
    pub session_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct WebFetchArgs {
    pub url: String,
    pub method: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub body: Option<String>,
    pub timeout_ms: Option<i64>,
}

#[derive(Clone)]
struct BackgroundSession {
    output: Arc<Mutex<Vec<u8>>>,
    exit_code: Arc<Mutex<Option<i32>>>,
    pid: i32,
    completion: Arc<Notify>,
}

#[derive(Clone)]
pub struct ShellToolServer {
    root: PathBuf,
    bash_path: PathBuf,
    tools: Arc<Vec<Tool>>,
    sessions: Arc<RwLock<HashMap<String, BackgroundSession>>>,
}

impl ShellToolServer {
    pub fn new(root: PathBuf, bash_path: PathBuf) -> Result<Self> {
        let normalized_root = fs::canonicalize(&root)
            .with_context(|| format!("Failed to canonicalize root {}", root.display()))?;

        let tools = vec![
            tool_schema::<ReadArgs>("read", "Read a file with optional encoding."),
            tool_schema::<EditArgs>(
                "edit",
                "Replace the first occurrence of a string in a file.",
            ),
            tool_schema::<WriteArgs>("write", "Create or overwrite a file with provided content."),
            tool_schema::<BashArgs>("bash", "Execute a shell command, optionally in background."),
            tool_schema::<BashOutputArgs>(
                "bash-output",
                "Stream output from a background shell session.",
            ),
            tool_schema::<KillShellArgs>("kill-shell", "Terminate a background shell session."),
            tool_schema::<WebFetchArgs>(
                "web-fetch",
                "Fetch content from an HTTP or HTTPS endpoint.",
            ),
        ];

        Ok(Self {
            root: normalized_root,
            bash_path,
            tools: Arc::new(tools),
            sessions: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub async fn serve_stdio(
        self,
    ) -> Result<RunningService<RoleServer, ShellToolServer>, rmcp::service::ServerInitializeError>
    where
        Self: Send + Sync + 'static,
    {
        self.serve(stdio()).await
    }

    fn resolve_path(&self, path: &str) -> Result<PathBuf, McpError> {
        let candidate = if Path::new(path).is_absolute() {
            PathBuf::from(path)
        } else {
            self.root.join(path)
        };

        let canonical = candidate.canonicalize().map_err(|err| {
            McpError::invalid_params(
                format!("Unable to resolve path {}: {err}", candidate.display()),
                None,
            )
        })?;

        if !canonical.starts_with(&self.root) {
            return Err(McpError::invalid_request(
                format!("Path {} escapes the configured root", canonical.display()),
                None,
            ));
        }

        Ok(canonical)
    }

    async fn read_file(&self, args: ReadArgs) -> Result<CallToolResult, McpError> {
        let path = self.resolve_path(&args.path)?;
        let data = tokio_fs::read(&path).await.map_err(|err| {
            McpError::internal_error(format!("Failed to read {}: {err}", path.display()), None)
        })?;

        let (content, encoding_label) = match args.encoding {
            ContentEncoding::Utf8 => {
                let text = String::from_utf8_lossy(&data).into_owned();
                (text, "utf-8".to_string())
            }
            ContentEncoding::Base64 => (BASE64_ENGINE.encode(data), "base64".to_string()),
        };

        Ok(CallToolResult::success(vec![Content::json(json!({
            "path": path,
            "encoding": encoding_label,
            "content": content,
        }))?]))
    }

    async fn write_file(&self, args: WriteArgs) -> Result<CallToolResult, McpError> {
        let candidate = if Path::new(&args.path).is_absolute() {
            PathBuf::from(&args.path)
        } else {
            self.root.join(&args.path)
        };

        let parent_dir = candidate
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| self.root.clone());

        tokio_fs::create_dir_all(&parent_dir).await.map_err(|err| {
            McpError::internal_error(
                format!(
                    "Failed to create parent dirs for {}: {err}",
                    candidate.display()
                ),
                None,
            )
        })?;

        let canonical_parent = parent_dir.canonicalize().map_err(|err| {
            McpError::invalid_params(
                format!("Unable to resolve parent {}: {err}", parent_dir.display()),
                None,
            )
        })?;

        if !canonical_parent.starts_with(&self.root) {
            return Err(McpError::invalid_request(
                format!("Path {} escapes the configured root", candidate.display()),
                None,
            ));
        }

        let file_name = candidate.file_name().ok_or_else(|| {
            McpError::invalid_params(
                format!("{} is missing a file name", candidate.display()),
                None,
            )
        })?;

        let path = canonical_parent.join(file_name);

        if !args.overwrite && path.exists() {
            return Err(McpError::invalid_params(
                format!("Refusing to overwrite existing file {}", path.display()),
                None,
            ));
        }

        if !args.create && !path.exists() {
            return Err(McpError::invalid_params(
                format!("File {} does not exist and create=false", path.display()),
                None,
            ));
        }

        let bytes = match args.encoding {
            ContentEncoding::Utf8 => args.content.into_bytes(),
            ContentEncoding::Base64 => BASE64_ENGINE
                .decode(args.content)
                .map_err(|err| McpError::invalid_params(err.to_string(), None))?,
        };

        let byte_count = i64::try_from(bytes.len())
            .map_err(|err| McpError::internal_error(err.to_string(), None))?;

        tokio_fs::write(&path, bytes).await.map_err(|err| {
            McpError::internal_error(format!("Failed to write {}: {err}", path.display()), None)
        })?;

        Ok(CallToolResult::success(vec![Content::json(json!({
            "path": path,
            "bytes_written": byte_count,
        }))?]))
    }

    async fn edit_file(&self, args: EditArgs) -> Result<CallToolResult, McpError> {
        let path = self.resolve_path(&args.path)?;
        let mut contents = tokio_fs::read_to_string(&path).await.map_err(|err| {
            McpError::internal_error(format!("Failed to read {}: {err}", path.display()), None)
        })?;

        if let Some(pos) = contents.find(&args.target) {
            contents.replace_range(pos..pos + args.target.len(), &args.replacement);
            tokio_fs::write(&path, contents).await.map_err(|err| {
                McpError::internal_error(format!("Failed to write {}: {err}", path.display()), None)
            })?;
            return Ok(CallToolResult::success(vec![Content::json(json!({
                "path": path,
                "replacements": 1,
            }))?]));
        }

        Err(McpError::resource_not_found(
            format!("Pattern not found in {}", path.display()),
            None,
        ))
    }

    fn build_command(&self, command: &str, cwd: &Path, env: &HashMap<String, String>) -> Command {
        let mut cmd = Command::new(&self.bash_path);
        cmd.arg("-lc").arg(command).current_dir(cwd);
        cmd.envs(env.iter());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        cmd
    }

    async fn run_foreground(
        &self,
        command: &str,
        cwd: &Path,
        env: &HashMap<String, String>,
    ) -> Result<CallToolResult, McpError> {
        let mut cmd = self.build_command(command, cwd, env);
        let output = cmd
            .output()
            .await
            .map_err(|err| McpError::internal_error(err.to_string(), None))?;

        let mut combined = output.stdout;
        combined.extend_from_slice(&output.stderr);
        let text_output = String::from_utf8_lossy(&combined).into_owned();
        let exit_code = exit_code_from_status(output.status);

        Ok(CallToolResult::success(vec![Content::json(json!({
            "exit_code": exit_code,
            "output": text_output,
        }))?]))
    }

    async fn spawn_background(
        &self,
        command: &str,
        cwd: &Path,
        env: &HashMap<String, String>,
    ) -> Result<String, McpError> {
        let mut cmd = self.build_command(command, cwd, env);
        let mut child = cmd
            .spawn()
            .map_err(|err| McpError::internal_error(err.to_string(), None))?;

        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let pid = child.id().ok_or_else(|| {
            McpError::internal_error("Failed to capture child pid".to_string(), None)
        })?;
        let pid =
            i32::try_from(pid).map_err(|err| McpError::internal_error(err.to_string(), None))?;

        let session = BackgroundSession {
            output: Arc::new(Mutex::new(Vec::new())),
            exit_code: Arc::new(Mutex::new(None)),
            pid,
            completion: Arc::new(Notify::new()),
        };

        let output_handle = session.output.clone();
        if let Some(stdout) = stdout {
            task::spawn(capture_stream(stdout, output_handle.clone()));
        }
        if let Some(stderr) = stderr {
            task::spawn(capture_stream(stderr, output_handle));
        }

        let exit_slot = session.exit_code.clone();
        let completion = session.completion.clone();
        task::spawn(async move {
            let status = child.wait().await.ok();
            let code = status.map(exit_code_from_status).unwrap_or(1);
            let mut exit_lock = exit_slot.lock().await;
            *exit_lock = Some(code);
            completion.notify_waiters();
        });

        let id = Uuid::new_v4().to_string();
        self.sessions.write().await.insert(id.clone(), session);
        Ok(id)
    }

    async fn collect_background_output(
        &self,
        session_id: &str,
        cursor: Option<i64>,
    ) -> Result<CallToolResult, McpError> {
        let sessions = self.sessions.read().await;
        let session = sessions.get(session_id).ok_or_else(|| {
            McpError::resource_not_found(format!("Unknown session {session_id}"), None)
        })?;

        let start = match cursor.unwrap_or(0) {
            value if value < 0 => {
                return Err(McpError::invalid_params(
                    "cursor must not be negative".to_string(),
                    None,
                ));
            }
            value => usize::try_from(value)
                .map_err(|err| McpError::invalid_params(err.to_string(), None))?,
        };

        let output_guard = session.output.lock().await;
        let slice = if start < output_guard.len() {
            &output_guard[start..]
        } else {
            &[]
        };
        let text = String::from_utf8_lossy(slice).into_owned();
        let next_cursor = i64::try_from(output_guard.len())
            .map_err(|err| McpError::internal_error(err.to_string(), None))?;
        drop(output_guard);

        let exit_code = *session.exit_code.lock().await;

        Ok(CallToolResult::success(vec![Content::json(json!({
            "session_id": session_id,
            "cursor": next_cursor,
            "output": text,
            "exit_code": exit_code,
        }))?]))
    }

    async fn kill_session(&self, session_id: &str) -> Result<CallToolResult, McpError> {
        let sessions = self.sessions.read().await;
        let session = sessions.get(session_id).ok_or_else(|| {
            McpError::resource_not_found(format!("Unknown session {session_id}"), None)
        })?;

        let result = unsafe { libc::kill(session.pid, libc::SIGTERM) };
        if result != 0 {
            return Err(McpError::internal_error(
                format!("Failed to send signal to {session_id}: {result}"),
                None,
            ));
        }

        let _ = timeout(Duration::from_secs(2), session.completion.notified()).await;
        let exit_code = *session.exit_code.lock().await;

        Ok(CallToolResult::success(vec![Content::json(json!({
            "session_id": session_id,
            "exit_code": exit_code,
            "signaled": true,
        }))?]))
    }

    async fn fetch(&self, args: WebFetchArgs) -> Result<CallToolResult, McpError> {
        let parsed = url::Url::parse(&args.url).map_err(|err| {
            McpError::invalid_params(format!("Invalid URL {}: {err}", args.url), None)
        })?;
        match parsed.scheme() {
            "http" | "https" => {}
            _ => {
                return Err(McpError::invalid_params(
                    format!("Unsupported scheme {}", parsed.scheme()),
                    None,
                ));
            }
        }

        let timeout_value = args
            .timeout_ms
            .and_then(|value| if value <= 0 { None } else { Some(value) })
            .map(|value| Duration::from_millis(value as u64))
            .unwrap_or(DEFAULT_FETCH_TIMEOUT);

        let client = reqwest::Client::builder()
            .timeout(timeout_value)
            .build()
            .map_err(|err| McpError::internal_error(err.to_string(), None))?;

        let method = args.method.as_deref().unwrap_or("GET");
        let method = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|err| McpError::invalid_params(err.to_string(), None))?;

        let mut request = client.request(method, parsed).headers(Default::default());

        if let Some(headers) = args.headers {
            let mut header_map = reqwest::header::HeaderMap::new();
            for (key, value) in headers {
                let header_name = reqwest::header::HeaderName::from_bytes(key.as_bytes())
                    .map_err(|err| McpError::invalid_params(err.to_string(), None))?;
                let header_value = reqwest::header::HeaderValue::from_str(&value)
                    .map_err(|err| McpError::invalid_params(err.to_string(), None))?;
                header_map.insert(header_name, header_value);
            }
            request = request.headers(header_map);
        }

        if let Some(body) = args.body {
            request = request.body(body);
        }

        let response = request
            .send()
            .await
            .map_err(|err| McpError::internal_error(err.to_string(), None))?;

        let status = response.status().as_u16();
        let mut headers = HashMap::new();
        for (key, value) in response.headers() {
            if let Ok(val) = value.to_str() {
                headers.insert(key.to_string(), val.to_string());
            }
        }

        let mut bytes = response
            .bytes()
            .await
            .map_err(|err| McpError::internal_error(err.to_string(), None))?
            .to_vec();
        let truncated = if bytes.len() > MAX_FETCH_BODY_BYTES {
            bytes.truncate(MAX_FETCH_BODY_BYTES);
            true
        } else {
            false
        };
        let body = String::from_utf8_lossy(&bytes).into_owned();

        Ok(CallToolResult::success(vec![Content::json(json!({
            "status": i32::from(status),
            "headers": headers,
            "body": body,
            "truncated": truncated,
        }))?]))
    }

    async fn handle_bash(&self, args: BashArgs) -> Result<CallToolResult, McpError> {
        let cwd = match args.cwd {
            Some(path) => self.resolve_path(&path)?,
            None => self.root.clone(),
        };
        let env = args.env.unwrap_or_default();

        if args.background {
            let session_id = self.spawn_background(&args.command, &cwd, &env).await?;
            return Ok(CallToolResult::success(vec![Content::json(json!({
                "session_id": session_id,
            }))?]));
        }

        self.run_foreground(&args.command, &cwd, &env).await
    }
}

impl ServerHandler for ShellToolServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2025_06_18,
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .enable_tool_list_changed()
                .build(),
            server_info: Implementation::from_build_env(),
            instructions: Some(
                "This server provides shell, file, and web-fetch tools. Paths are constrained to the configured root."
                    .to_string(),
            ),
        }
    }

    async fn initialize(
        &self,
        _request: InitializeRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, McpError> {
        Ok(self.get_info())
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParam>,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, McpError>> + Send + '_ {
        let tools = self.tools.clone();
        async move {
            Ok(ListToolsResult {
                tools: (*tools).clone(),
                next_cursor: None,
            })
        }
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        match request.name.as_ref() {
            "read" => {
                let args: ReadArgs = parse_args(request.arguments)?;
                self.read_file(args).await
            }
            "edit" => {
                let args: EditArgs = parse_args(request.arguments)?;
                self.edit_file(args).await
            }
            "write" => {
                let args: WriteArgs = parse_args(request.arguments)?;
                self.write_file(args).await
            }
            "bash" => {
                let args: BashArgs = parse_args(request.arguments)?;
                self.handle_bash(args).await
            }
            "bash-output" => {
                let args: BashOutputArgs = parse_args(request.arguments)?;
                self.collect_background_output(&args.session_id, args.cursor)
                    .await
            }
            "kill-shell" => {
                let args: KillShellArgs = parse_args(request.arguments)?;
                self.kill_session(&args.session_id).await
            }
            "web-fetch" => {
                let args: WebFetchArgs = parse_args(request.arguments)?;
                self.fetch(args).await
            }
            other => Err(McpError::invalid_params(
                format!("Unknown tool {other}"),
                None,
            )),
        }
    }
}

fn tool_schema<T: JsonSchema>(name: &str, description: &str) -> Tool {
    let schema = schemars::schema_for!(T);
    #[expect(clippy::expect_used)]
    let json_object: JsonObject = serde_json::from_value(
        serde_json::to_value(schema).expect("schema serialization must succeed"),
    )
    .expect("schema must deserialize to map");

    Tool::new(
        Cow::Owned(name.to_string()),
        Cow::Owned(description.to_string()),
        Arc::new(json_object),
    )
}

fn parse_args<T: for<'de> Deserialize<'de>>(arguments: Option<JsonObject>) -> Result<T, McpError> {
    let map = arguments.ok_or_else(|| {
        McpError::invalid_params("Missing arguments for tool invocation".to_string(), None)
    })?;
    serde_json::from_value(serde_json::Value::Object(map))
        .map_err(|err| McpError::invalid_params(err.to_string(), None))
}

async fn capture_stream<R>(mut reader: R, output: Arc<Mutex<Vec<u8>>>)
where
    R: AsyncReadExt + Unpin,
{
    let mut buffer = [0_u8; 4096];
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) => break,
            Ok(size) => {
                let mut guard = output.lock().await;
                guard.extend_from_slice(&buffer[..size]);
            }
            Err(_) => break,
        }
    }
}

fn exit_code_from_status(status: std::process::ExitStatus) -> i32 {
    match status.code() {
        Some(code) => code,
        None => {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                status.signal().map(|signal| -signal).unwrap_or(1)
            }
            #[cfg(not(unix))]
            {
                1
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use std::collections::HashMap;
    use tempfile::tempdir;
    use tokio::time::Duration;
    use tokio::time::sleep;

    fn bash_path() -> PathBuf {
        PathBuf::from("/bin/bash")
    }

    #[tokio::test]
    async fn write_and_read_round_trip() -> Result<()> {
        let dir = tempdir()?;
        let server = ShellToolServer::new(dir.path().to_path_buf(), bash_path())?;

        let write_args = WriteArgs {
            path: "sample.txt".to_string(),
            content: "hello world".to_string(),
            encoding: ContentEncoding::Utf8,
            create: true,
            overwrite: true,
        };
        server.write_file(write_args).await?;

        let disk_contents = tokio_fs::read_to_string(dir.path().join("sample.txt")).await?;
        assert_eq!(disk_contents, "hello world");

        let read_result = server
            .read_file(ReadArgs {
                path: "sample.txt".to_string(),
                encoding: ContentEncoding::Utf8,
            })
            .await?;

        let serialized = serde_json::to_value(&read_result.content[0])?;
        let text_field = serialized
            .get("text")
            .and_then(|value| value.as_str())
            .expect("content text should exist");
        let parsed: serde_json::Value = serde_json::from_str(text_field)?;
        assert_eq!(parsed.get("content"), Some(&json!("hello world")));

        Ok(())
    }

    #[tokio::test]
    async fn edit_replaces_first_match() -> Result<()> {
        let dir = tempdir()?;
        let server = ShellToolServer::new(dir.path().to_path_buf(), bash_path())?;
        let write_args = WriteArgs {
            path: "story.txt".to_string(),
            content: "abc abc".to_string(),
            encoding: ContentEncoding::Utf8,
            create: true,
            overwrite: true,
        };
        server.write_file(write_args).await?;

        server
            .edit_file(EditArgs {
                path: "story.txt".to_string(),
                target: "abc".to_string(),
                replacement: "xyz".to_string(),
            })
            .await?;

        let updated = tokio_fs::read_to_string(dir.path().join("story.txt")).await?;
        assert_eq!(updated, "xyz abc");
        Ok(())
    }

    #[tokio::test]
    async fn background_bash_records_output() -> Result<()> {
        let dir = tempdir()?;
        let server = ShellToolServer::new(dir.path().to_path_buf(), bash_path())?;
        let env = HashMap::new();
        let session_id = server
            .spawn_background("echo background", dir.path(), &env)
            .await?;

        sleep(Duration::from_millis(200)).await;

        let sessions = server.sessions.read().await;
        let session = sessions
            .get(&session_id)
            .expect("session should be registered");
        let completion = session.completion.clone();
        drop(sessions);

        completion.notified().await;

        let sessions = server.sessions.read().await;
        let session = sessions
            .get(&session_id)
            .expect("session should be registered");
        let output = session.output.lock().await.clone();
        let text = String::from_utf8_lossy(&output);
        assert!(text.contains("background"));
        Ok(())
    }
}
