// Uses the same fetch helper as the redirect screen. Render all server values as text.
let dnsInitialized = false;
let dnsBusy = false;
let hostnameBusy = false;

function updateHostnameRules(rules) {
  const select = document.getElementById("hostname-rule");
  const selected = select.value;
  select.replaceChildren(new Option("Choose a TCP redirect", ""));
  for (const rule of rules) {
    if (rule.protocol !== "tcp" || !rule.match_ip || rule.match_ip === "0.0.0.0") continue;
    select.add(new Option(`${rule.match_ip}:${rule.match_port} → ${rule.tailscale_peer || rule.target_ip}:${rule.target_port}`, rule.handle_id));
  }
  if ([...select.options].some(option => option.value === selected)) select.value = selected;
  document.getElementById("hostname-submit").disabled = hostnameBusy || select.options.length === 1;
  if (select.options.length === 1) select.options[0].textContent = "Create a TCP redirect with a LAN IP first";
}

async function loadDNS(populate = false) {
  const refresh = document.getElementById("refresh-dns");
  refresh.disabled = true;
  try {
    const data = await fetchJSON("/api/dns");
    const settings = data.settings;
    const status = data.status;
    const ipSelect = document.getElementById("dns-ip");
    {
      const selected = ipSelect.value;
      const addresses = await fetchJSON("/api/lan-addresses");
      ipSelect.replaceChildren(new Option("Choose a LAN address", ""));
      for (const address of addresses) ipSelect.add(new Option(`${address.ip} (${address.interface})`, address.ip));
      if (settings.listen_ip && ![...ipSelect.options].some(option => option.value === settings.listen_ip)) {
        ipSelect.add(new Option(`${settings.listen_ip} (not assigned to this machine)`, settings.listen_ip));
      }
      if (selected && ![...ipSelect.options].some(option => option.value === selected)) {
        ipSelect.add(new Option(`${selected} (not assigned to this machine)`, selected));
      }
      ipSelect.value = selected;
    }
    if (!dnsInitialized || populate) {
      ipSelect.value = settings.listen_ip || "";
      document.getElementById("dns-enabled").checked = settings.enabled;
      document.getElementById("dns-fields").disabled = false;
    }
    dnsInitialized = true;
    document.getElementById("dns-status").textContent = status.dns.running ? "Running" : settings.enabled ? "Needs attention" : "Disabled";
    document.getElementById("dns-client-address").textContent = settings.listen_ip || "the LAN address selected here";
    document.getElementById("dns-upstreams").textContent = status.dns.upstreams?.join(", ") || (settings.enabled ? "No network DNS found yet" : "Discovered automatically when enabled");
    document.getElementById("dns-config-path").textContent = status.config_path;
    document.getElementById("dns-error").textContent = [status.dns.error, status.restore_error].filter(Boolean).join(" ");
    const list = document.getElementById("hostname-list");
    list.replaceChildren();
    for (const record of data.hostnames) {
      const row = document.createElement("li");
      const description = document.createElement("div");
      const name = document.createElement("strong");
      name.textContent = record.name;
      const detail = document.createElement("span");
      detail.className = "rule-detail";
      detail.textContent = `Resolves to ${record.address} · TCP ${record.port} → ${record.destination}`;
      description.append(name, detail);
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "danger";
      remove.textContent = "Remove";
      remove.dataset.hostname = record.name;
      remove.setAttribute("aria-label", `Remove hostname ${record.name}`);
      row.append(description, remove);
      list.append(row);
    }
    if (!data.hostnames.length) {
      const empty = document.createElement("li");
      empty.className = "muted";
      empty.textContent = "No hostnames yet. Add a name to resolve it to your redirect’s LAN address.";
      list.append(empty);
    }
  } catch (error) {
    document.getElementById("dns-error").textContent = `Could not load DNS settings. ${error.message}`;
    document.getElementById("dns-status").textContent = "Unavailable";
  } finally { refresh.disabled = false; }
}

// The script is loaded after the forms and before the shared inline helpers.
document.getElementById("dns-form").addEventListener("submit", async event => {
  event.preventDefault();
  if (dnsBusy) return;
  dnsBusy = true;
  const fields = document.getElementById("dns-fields");
  const button = fields.querySelector("button");
  const settings = { enabled: document.getElementById("dns-enabled").checked, listen_ip: document.getElementById("dns-ip").value };
  fields.disabled = true;
  button.textContent = "Saving…";
  document.getElementById("dns-notice").textContent = "";
  try {
    await fetchJSON("/api/dns", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(settings) });
    await loadDNS(true);
    document.getElementById("dns-notice").textContent = settings.enabled ? "DNS settings saved. Configure DHCP to use this address." : "DNS forwarding disabled. Settings saved.";
  } catch (error) {
    document.getElementById("dns-error").textContent = error.message;
  } finally { fields.disabled = false; button.textContent = "Save DNS settings"; dnsBusy = false; }
});

document.getElementById("hostname-form").addEventListener("submit", async event => {
  event.preventDefault();
  const button = document.getElementById("hostname-submit");
  if (button.disabled || hostnameBusy) return;
  hostnameBusy = true;
  button.disabled = true;
  button.textContent = "Adding…";
  document.getElementById("hostname-error").textContent = "";
  document.getElementById("hostname-notice").textContent = "";
  try {
    await fetchJSON("/api/hostnames", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ hostname: document.getElementById("hostname").value, rule_handle: document.getElementById("hostname-rule").value }) });
    document.getElementById("hostname").value = "";
    await loadDNS();
    document.getElementById("hostname-notice").textContent = "Hostname saved. DNS clients use the new answer after their cached answer expires.";
  } catch (error) { document.getElementById("hostname-error").textContent = error.message; }
  finally { hostnameBusy = false; button.disabled = document.getElementById("hostname-rule").options.length === 1; button.textContent = "Add hostname"; }
});

document.getElementById("hostname-list").addEventListener("click", async event => {
  const button = event.target.closest("button[data-hostname]");
  if (!button || button.disabled || !confirm(`Remove the local DNS override for ${button.dataset.hostname}?`)) return;
  button.disabled = true;
  button.textContent = "Removing…";
  document.getElementById("hostname-error").textContent = "";
  try {
    await fetchJSON(`/api/hostnames/${encodeURIComponent(button.dataset.hostname)}`, { method: "DELETE" });
    await loadDNS();
    document.getElementById("hostname-notice").textContent = "Hostname removed. Its forwarding rule remains available.";
    document.getElementById("hostname").focus();
  } catch (error) { document.getElementById("hostname-error").textContent = error.message; }
  finally { button.disabled = false; button.textContent = "Remove"; }
});

document.getElementById("refresh-dns").addEventListener("click", () => loadDNS());
document.getElementById("run-checks").addEventListener("click", async () => {
  const button = document.getElementById("run-checks");
  button.disabled = true;
  button.textContent = "Checking…";
  const list = document.getElementById("diagnostic-list");
  list.replaceChildren();
  try {
    const checks = await fetchJSON("/api/diagnostics", { method: "POST" });
    for (const check of checks) {
      const item = document.createElement("li");
      const label = document.createElement("strong");
      label.className = check.ok ? "notice" : "error";
      label.textContent = `${check.ok ? "Pass" : "Needs attention"}: ${check.name}`;
      const detail = document.createElement("span");
      detail.className = "rule-detail";
      detail.textContent = check.detail;
      item.append(label, detail);
      list.append(item);
    }
    await loadDNS();
  } catch (error) { const item = document.createElement("li"); item.className = "error"; item.textContent = error.message; list.append(item); }
  finally { button.disabled = false; button.textContent = "Run checks"; }
});
