defmodule APayToolPrivateTest do
  use ExUnit.Case

  alias :apay_tool, as: Tool

  test "basic usage" do
    config = Tool.config %{
      # private_key: File.read!("test/fixtures/private/pkey.pem")
      private_key: fn (_pubkey_hash_from_token) ->
        File.read!("test/fixtures/private/pkey_ec.pem")
      end,

      # merchant_id: fn (_pubkey_hash_from_token) -> {:raw,  "merchant.com.seatgeek.SeatGeek"} end,
      merchant_id: {:raw, "merchant.bank131"},

      # verify_signing_time: :false,
      verify_signing_time: fn (ts) ->
        assert :calendar.gregorian_seconds_to_datetime(ts) == {{2022, 2, 1}, {13, 16, 42}}
      end,

      certificate_root: File.read!("test/fixtures/AppleRootCA-G3.cer"),
    }
    token = File.read!("test/fixtures/private/token_ec.json") |> Jason.decode! |> Tool.parse(config)
    assert Tool.verify(token, config)

    decoded = Tool.decrypt(token, config) |> Jason.decode!
    assert decoded["applicationPrimaryAccountNumber"] != nil
  end
end
