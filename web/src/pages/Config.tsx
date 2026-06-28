export default function Config() {
  return (
    <>
      <p>Configuration is loaded from <code>/etc/vakta/config.yaml</code> on agent startup.</p>
      <p>Edit the file and restart the agent to apply changes, or use <code>POST /api/v1/rules/reload</code> for hot-reload of rules only.</p>
    </>
  );
}
