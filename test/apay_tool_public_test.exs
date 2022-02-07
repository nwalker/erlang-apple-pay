defmodule APayToolPublicTest do
  use ExUnit.Case

  alias :apay_tool, as: Tool

  test "basic usage" do
    config = Tool.config %{
      # private_key: File.read!("test/fixtures/public/pkey.pem")
      private_key: fn (_pubkey_hash_from_token) ->
        File.read!("test/fixtures/public/pkey_ec.pem")
      end,

      # merchant_id: fn (_pubkey_hash_from_token) -> {:raw,  "merchant.com.seatgeek.SeatGeek"} end,
      merchant_id: {:sha, :crypto.hash(:sha256, "merchant.com.seatgeek.SeatGeek")},

      # verify_signing_time: :false,
      verify_signing_time: fn (ts) ->
        assert :calendar.gregorian_seconds_to_datetime(ts) == {{2014, 10, 27}, {19, 51, 43}}
      end,

      # certificate_root: File.read!("test/fixtures/AppleRootCA-G3.cer"),
      skip_chain_verification: :true,
    }
    token = File.read!("test/fixtures/public/token_ec.json") |> Jason.decode! |> Tool.parse(config)
    assert Tool.verify(token, config)

    decoded = Tool.decrypt(token, config) |> Jason.decode!
    assert decoded["applicationPrimaryAccountNumber"] != nil
  end
end
