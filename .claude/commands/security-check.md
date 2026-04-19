Run the project security check workflow.

Use the `security-check` MCP server's `security_check` tool first.

Arguments:
- If the user provides a project path, pass it as `base_path`.
- If the user provides a deployed URL, pass it as `target_url`.
- If the user provides an OpenAPI or Swagger document URL, pass it as `openapi_url`.
- If the user provides normal-user auth data, pass it to `bearer_token`, `session_cookie`, or `extra_headers`.
- If the user asks to save a report, pass `output_path` and set `allowed_base_path` to the target project root.

After the MCP result is available, perform a security-review style code review of the same target. Focus on issues the MCP may miss:

- Authorization and role checks
- IDOR and ownership validation
- OpenAPI-discovered high-risk endpoints and request fields
- Business logic flaws in order, payment, refund, coupon, invitation, account, upload, download, and webhook flows
- Server-side trust of client-controlled fields such as `role`, `isAdmin`, `userId`, `ownerId`, `price`, `amount`, `status`, `discount`, and `quantity`
- Missing rate limits or replay protection on sensitive state changes
- Weak token, password reset, session, and webhook verification flows

Return a combined result:

1. MCP findings summary
2. Additional security-review findings
3. Release decision
4. Prioritized fixes
5. Remaining manual checks
