local http = require("socket.http")
local test_support = require("test_support")
require 'busted.runner'()

describe("when revocation_fail_mode is closed and the revocation store is unreachable during logout", function()
  test_support.start_server({
    revocation_test = {
      fail_mode = "closed",
      set_fails = true,
    },
    unauth_action = "deny",
  })
  teardown(test_support.stop_server)

  local _, _, cookie = test_support.login()

  local body, status = http.request({
    url = "http://127.0.0.1/default/logout",
    headers = { cookie = cookie },
    redirect = false,
  })

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
