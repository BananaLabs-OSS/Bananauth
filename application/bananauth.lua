-- Bananauth application logic. Stateful session lifecycle belongs to the
-- generic auth-session owner; this script owns sequencing and projections.
-- The compatibility cell intentionally retains the historical "bananauth"
-- identity so its Pulp-scoped account database does not move during cutover.

local SESSION_OWNER = "auth-session"
local IDENTITY_OWNER = "auth-identity"

local function decode_request(payload)
  if type(payload) ~= "table" or type(payload.request_msgpack) ~= "string" then
    error("bananauth workflow requires request_msgpack")
  end
  local request = pulp.unpack(payload.request_msgpack)
  if type(request) ~= "table" then
    error("bananauth workflow request must decode to a table")
  end
  return request
end

local function owner_call(target, provider, request)
  local raw = pulp.call_raw(target, provider, pulp.pack(request))
  local result = pulp.unpack(raw)
  local expected = target == SESSION_OWNER and "auth-session.v1" or "auth-identity.v1"
  if type(result) ~= "table" or result.version ~= expected then
    error(target .. " owner returned an invalid contract")
  end
  return pulp.pack(result)
end

pulp.on("bananauth.session.created.v1", function(payload)
  return owner_call(SESSION_OWNER, "auth.session.v1.create", decode_request(payload))
end)

pulp.on("bananauth.session.verified.v1", function(payload)
  return owner_call(SESSION_OWNER, "auth.session.v1.get", decode_request(payload))
end)

pulp.on("bananauth.session.revoked.v1", function(payload)
  return owner_call(SESSION_OWNER, "auth.session.v1.revoke", decode_request(payload))
end)

local IDENTITY_EVENTS = {
  ["bananauth.identity.native.register.v1"] = "auth.identity.v1.native.register",
  ["bananauth.identity.native.authenticate.v1"] = "auth.identity.v1.native.authenticate",
  ["bananauth.identity.native.password.change.v1"] = "auth.identity.v1.native.password.change",
  ["bananauth.identity.native.attach.v1"] = "auth.identity.v1.native.attach",
  ["bananauth.identity.password-reset.issue.v1"] = "auth.identity.v1.password-reset.issue",
  ["bananauth.identity.password-reset.consume.v1"] = "auth.identity.v1.password-reset.consume",
  ["bananauth.identity.email-verification.issue.v1"] = "auth.identity.v1.email-verification.issue",
  ["bananauth.identity.email-verification.consume.v1"] = "auth.identity.v1.email-verification.consume",
  ["bananauth.identity.account.delete.v1"] = "auth.identity.v1.account.delete",
  ["bananauth.identity.oauth-state.issue.v1"] = "auth.identity.v1.oauth-state.issue",
  ["bananauth.identity.oauth-state.consume.v1"] = "auth.identity.v1.oauth-state.consume",
  ["bananauth.identity.oauth.resolve.v1"] = "auth.identity.v1.oauth.resolve",
  ["bananauth.identity.oauth.upsert.v1"] = "auth.identity.v1.oauth.upsert",
  ["bananauth.identity.profile.create.v1"] = "auth.identity.v1.profile.create",
  ["bananauth.identity.profile.get.v1"] = "auth.identity.v1.profile.get",
  ["bananauth.identity.profile.update.v1"] = "auth.identity.v1.profile.update",
  ["bananauth.identity.rate.check.v1"] = "auth.identity.v1.rate.check",
  ["bananauth.identity.rate.clear.v1"] = "auth.identity.v1.rate.clear",
  ["bananauth.identity.legacy.import.v1"] = "auth.identity.v1.legacy.import",
}

for event, provider in pairs(IDENTITY_EVENTS) do
  pulp.on(event, function(payload)
    return owner_call(IDENTITY_OWNER, provider, decode_request(payload))
  end)
end
