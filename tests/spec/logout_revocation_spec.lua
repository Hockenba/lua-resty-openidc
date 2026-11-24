local http = require("socket.http")
local ltn12 = require("ltn12")
local mime = require("mime")
local test_support = require("test_support")
require 'busted.runner'()

-- the key under which the revocation store has the session id of a cookie: the
-- session id is the 32 bytes that follow the 3 byte type and flags of the header
local function session_id_key(cookie)
  local value = cookie:match("^[^=]+=([^;]+)")
  local header = value:sub(1, 48):gsub("-", "+"):gsub("_", "/")
  local sid = mime.unb64(header):sub(4, 35)
  return (mime.b64(sid):gsub("%+", "-"):gsub("/", "_"):gsub("=", ""))
end

local function revocation_has(key)
  local body = http.request("http://127.0.0.1/revocation-has?key=" .. key)
  return body:match("yes") ~= nil
end

describe("when session startup returns no session", function()
  test_support.start_server({
    session_start_fails = true,
  })
  teardown(test_support.stop_server)

  local response_body = {}
  local _, status = http.request({
    url = "http://127.0.0.1/default/t",
    redirect = false,
    sink = ltn12.sink.table(response_body),
  })

  it("returns the startup error without authenticating the request", function()
    assert.are.equals(401, status)
    assert.truthy(string.find(table.concat(response_body), "session start failed", 1, true))
  end)
end)

describe("when revocation_fail_mode is closed and the revocation store read fails", function()
  test_support.start_server({
    revocation_test = {
      fail_mode = "closed",
    },
  })
  teardown(test_support.stop_server)

  local _, _, cookie = test_support.login()
  test_support.fail_revocation_reads()

  local response_body = {}
  local _, status = http.request({
    url = "http://127.0.0.1/default/t",
    headers = { cookie = cookie },
    redirect = false,
    sink = ltn12.sink.table(response_body),
  })
  local body = table.concat(response_body)

  it("propagates the session start failure", function()
    assert.are.equals(401, status)
    assert.truthy(string.find(body, "unable to check session revocation", 1, true))
  end)

  it("does not authenticate the request", function()
    assert.is_nil(string.find(body, "hello, world!", 1, true))
  end)
end)

describe("when revocation_fail_mode is open and the revocation store read fails", function()
  test_support.start_server({
    revocation_test = {
      fail_mode = "open",
    },
  })
  teardown(test_support.stop_server)

  local _, _, cookie = test_support.login()
  test_support.fail_revocation_reads()

  local response_body = {}
  local _, status = http.request({
    url = "http://127.0.0.1/default/t",
    headers = { cookie = cookie },
    redirect = false,
    sink = ltn12.sink.table(response_body),
  })

  it("authenticates the request", function()
    assert.are.equals(200, status)
    assert.truthy(string.find(table.concat(response_body), "hello, world!", 1, true))
  end)
end)

describe("when revocation_fail_mode is closed and the revocation store is unreachable during logout", function()
  test_support.start_server({
    revocation_test = {
      fail_mode = "closed",
      set_fails = true,
    },
  })
  teardown(test_support.stop_server)

  local _, _, cookie = test_support.login()

  local response_body = {}
  local _, status = http.request({
    url = "http://127.0.0.1/default/logout",
    headers = { cookie = cookie },
    redirect = false,
    sink = ltn12.sink.table(response_body),
  })
  local body = table.concat(response_body)

  it("propagates destroy failure", function()
    assert.are.equals(401, status)
    assert.truthy(string.find(body, "unable to mark session revoked", 1, true))
  end)

  it("leaves the session valid for replay", function()
    local _, replay_status = http.request({
      url = "http://127.0.0.1/default/t",
      headers = { cookie = cookie },
      redirect = false,
    })
    assert.are.equals(200, replay_status)
  end)
end)

describe("when revocation_fail_mode is open and the revocation store is unreachable during logout", function()
  test_support.start_server({
    revocation_test = {
      fail_mode = "open",
      set_fails = true,
    },
  })
  teardown(test_support.stop_server)

  local _, _, cookie = test_support.login()

  local _, status = http.request({
    url = "http://127.0.0.1/default/logout",
    headers = { cookie = cookie },
    redirect = false,
  })

  it("logout still completes", function()
    assert.are.equals(200, status)
  end)
end)

describe("when a logout opens a session that is due for a rolling refresh", function()
  test_support.start_server({
    revocation_test = {
      fail_mode = "closed",
      rolling_timeout = 20,
    },
  })
  teardown(test_support.stop_server)

  local _, _, cookie = test_support.login()

  -- past 75% of the rolling timeout, where start() would save the session
  -- under a new session id
  os.execute("sleep 16")

  local _, logout_status = http.request({
    url = "http://127.0.0.1/default/logout",
    headers = { cookie = cookie },
    redirect = false,
  })

  it("logout completes", function()
    assert.are.equals(200, logout_status)
  end)

  it("revokes the session id of the cookie presented at logout", function()
    local _, replay_status = http.request({
      url = "http://127.0.0.1/default/t",
      headers = { cookie = cookie },
      redirect = false,
    })
    assert.are.equals(302, replay_status)
  end)

  -- With the lineage revocation of lua-resty-session the replay is rejected
  -- whichever session id gets marked, so check the mark itself: after a refresh
  -- at logout it would be the one of the rotated session.
  it("did not refresh the session before revoking it", function()
    assert.is_true(revocation_has(session_id_key(cookie)))
  end)
end)
