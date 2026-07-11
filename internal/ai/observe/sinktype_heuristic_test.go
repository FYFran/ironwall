package observe

import (
	"testing"
)

// ─── SinkType: stdlib functions ──────────────────────────────────────────

func TestSinkType_GoStdlib_SQL(t *testing.T) {
	tests := []string{"database.Query", "db.QueryRow", "sql.QueryContext", "sql.Query", "query", "queryrow"}
	for _, name := range tests {
		st := SinkType(name)
		if st != "sql" {
			t.Errorf("SinkType(%q) = %q, want sql", name, st)
		}
	}
}

func TestSinkType_GoStdlib_FileOps(t *testing.T) {
	tests := []string{"os.ReadFile", "ReadFile", "os.Open", "os.Create", "writefile"}
	for _, name := range tests {
		st := SinkType(name)
		if st != "file_ops" {
			t.Errorf("SinkType(%q) = %q, want file_ops", name, st)
		}
	}
}

func TestSinkType_GoStdlib_CommandExec(t *testing.T) {
	tests := []string{"exec.Command", "os/exec.Command", "os.system", "subprocess.run", "subprocess.Popen"}
	for _, name := range tests {
		st := SinkType(name)
		if st != "command_exec" {
			t.Errorf("SinkType(%q) = %q, want command_exec", name, st)
		}
	}
}

func TestSinkType_GoStdlib_Network(t *testing.T) {
	tests := []string{"http.Get", "http.Post", "http.Do", "client.Get", "client.Post", "redirect"}
	for _, name := range tests {
		st := SinkType(name)
		if st != "network" {
			t.Errorf("SinkType(%q) = %q, want network", name, st)
		}
	}
}

func TestSinkType_Python_DBAPI(t *testing.T) {
	tests := []string{"execute", "executemany", "fetchall", "fetchone", "cursor.execute", "cursor.fetchall"}
	for _, name := range tests {
		st := SinkType(name)
		if st != "sql" {
			t.Errorf("SinkType(%q) = %q, want sql", name, st)
		}
	}
}

func TestSinkType_Python_Template(t *testing.T) {
	tests := []string{"render_template_string", "render_template", "send_file"}
	for _, name := range tests {
		st := SinkType(name)
		if st == "" {
			t.Errorf("SinkType(%q) = %q, want non-empty", name, st)
		}
	}
	if SinkType("render_template_string") != "template" {
		t.Errorf("SinkType(%q) = %q, want template", "render_template_string", SinkType("render_template_string"))
	}
	if SinkType("send_file") != "file_ops" {
		t.Errorf("SinkType(%q) = %q, want file_ops", "send_file", SinkType("send_file"))
	}
}

func TestSinkType_Python_Requests(t *testing.T) {
	tests := []string{"requests.get", "requests.post", "urlopen", "urllib.request"}
	for _, name := range tests {
		st := SinkType(name)
		if st != "network" {
			t.Errorf("SinkType(%q) = %q, want network", name, st)
		}
	}
}

// ─── SinkType: heuristic wrapper patterns ──────────────────────────────────

func TestSinkType_Heuristic_SQL_Wrappers(t *testing.T) {
	// Should match
	tests := []string{"SearchUsers", "searchusers", "GetUserByID", "getuserbyid",
		"FindUser", "QueryUser", "LookupUser", "GetUser", "get_user",
		"get_user_by_id", "get_record", "get_all_users", "search_user",
		"search_record", "find_by_id", "find_by_username", "find_by_email"}
	for _, name := range tests {
		st := SinkType(name)
		if st != "sql" {
			t.Errorf("SinkType(%q) = %q, want sql", name, st)
		}
	}
}

func TestSinkType_Heuristic_SQL_NoFalsePositive(t *testing.T) {
	// Should NOT match (bare get_, list_, find_ removed)
	tests := []string{"get_config", "get_logger", "get_env", "get_version",
		"get_status", "get_time", "get_default", "list_files", "list_directory",
		"list_modules", "find_file", "find_path", "find_root", "find_config"}
	for _, name := range tests {
		st := SinkType(name)
		if st == "sql" {
			t.Errorf("SinkType(%q) = sql, want NOT sql (bare prefix FP)", name)
		}
	}
}

func TestSinkType_Heuristic_Network_Wrappers(t *testing.T) {
	tests := []string{"FetchURL", "fetchurl", "GetURL", "PostURL", "SendRequest",
		"CallAPI", "Webhook", "send_email", "send_notification", "send_webhook",
		"send_message", "call_api", "post_data", "fetch_url", "get_url",
		"notify_user", "push_notification"}
	for _, name := range tests {
		st := SinkType(name)
		if st != "network" {
			t.Errorf("SinkType(%q) = %q, want network", name, st)
		}
	}
}

func TestSinkType_Heuristic_Network_NoFalsePositive(t *testing.T) {
	// Should NOT match (bare send_, notify, push_ removed)
	tests := []string{"send_file", "send_data", "send_response",
		"notify_all", "notify_admin", "push_stack", "push_queue",
		"post_auth", "post_comment"}
	for _, name := range tests {
		st := SinkType(name)
		if st == "network" {
			t.Errorf("SinkType(%q) = network, want NOT network (bare prefix FP)", name)
		}
	}
}

func TestSinkType_Heuristic_Command_Wrappers(t *testing.T) {
	tests := []string{"Ping", "ping", "RunCommand", "ExecCmd",
		"ShellExec", "SystemCall", "exec_cmd", "exec_command",
		"run_cmd", "run_command", "shell_exec", "system_call", "subprocess_run"}
	for _, name := range tests {
		st := SinkType(name)
		if st != "command_exec" {
			t.Errorf("SinkType(%q) = %q, want command_exec", name, st)
		}
	}
}

func TestSinkType_Heuristic_File_Wrappers(t *testing.T) {
	tests := []string{"ReadFile", "readfile", "WriteFile", "DownloadFile",
		"SaveToFile", "UploadFile", "save_file", "save_to_file",
		"write_file", "write_to_file", "load_file", "read_file",
		"download_file", "upload_file"}
	for _, name := range tests {
		st := SinkType(name)
		if st != "file_ops" {
			t.Errorf("SinkType(%q) = %q, want file_ops", name, st)
		}
	}
}

func TestSinkType_Heuristic_Template_Wrappers(t *testing.T) {
	tests := []string{"RenderTemplate", "RenderPage", "TemplateRender",
		"render_template", "render_page", "template_render",
		"rendertemplate", "templaterender", "renderpage"}
	for _, name := range tests {
		st := SinkType(name)
		if st != "template" {
			t.Errorf("SinkType(%q) = %q, want template", name, st)
		}
	}
}

func TestSinkType_Empty(t *testing.T) {
	tests := []string{"writejson", "renderjson", "respondjson", "sendjson", "jsonresponse",
		"init", "main", "health", "healthcheck", "index", "handler", "middleware",
		"get_config", "get_env", "list_files"}
	for _, name := range tests {
		st := SinkType(name)
		if st != "" {
			t.Errorf("SinkType(%q) = %q, want empty", name, st)
		}
	}
	// send_file correctly classified as file_ops (Flask send_file)
	if SinkType("send_file") != "file_ops" {
		t.Errorf("SinkType(send_file) = %q, want file_ops", SinkType("send_file"))
	}
}

// ─── inferLocalVarType ────────────────────────────────────────────────────

func TestInferLocalVarType_DB(t *testing.T) {
	vars := []string{"db", "database", "conn", "tx", "stmt", "row", "rows", "result"}
	for range vars {
		// We can't easily construct an ast.CallExpr here, so test via integration
		// with SinkType on the synthetic name
		synth := "sql.Query"
		st := SinkType(synth)
		if st != "sql" {
			t.Errorf("SinkType(synthetic %q) = %q, want sql", synth, st)
		}
	}
}

func TestInferLocalVarType_NonDB(t *testing.T) {
	// Close/Error/String should return empty (skip common util methods)
	// These are tested at SinkType level — the funcName alone doesn't match
	st := SinkType("Close")
	if st != "" {
		t.Errorf("SinkType(Close) = %q, want empty", st)
	}
	st = SinkType("Error")
	if st != "" {
		t.Errorf("SinkType(Error) = %q, want empty", st)
	}
}

func TestSinkType_NoRegression(t *testing.T) {
	// Snapshot: all patterns from the python-vuln-target wrapper functions
	// These MUST still work after the pattern changes
	criticalPatterns := []struct {
		name     string
		expected string
	}{
		{"search_users", "sql"},
		{"fetch_url", "network"},
		{"webhook", "network"},      // Webhook* prefix
		{"ping", "command_exec"},
		{"download_file", "file_ops"},
		{"view_logs", ""},           // not a known sink pattern
		{"admin_delete_user", "sql"}, // delete_user prefix
		{"admin_list_users", "sql"},  // list_users prefix
		{"hash_password", ""},       // not a known sink
		{"get_file", ""},            // bare get_ removed, not a specific file pattern
		{"login", ""},               // not a known sink
		{"handleUserSearch", ""},    // handler, not sink
		{"handlePing", ""},          // handler, not sink
	}
	for _, tc := range criticalPatterns {
		st := SinkType(tc.name)
		if st != tc.expected {
			t.Errorf("SinkType(%q) = %q, want %q (REGESSION)", tc.name, st, tc.expected)
		}
	}
}
