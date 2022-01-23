defmodule ApayDecryptExTest do
  use ExUnit.Case

  test "apay decrypt happy path" do
    token =
      File.read!("./priv/token.json")
      |> Jason.decode!()

    raw_pkey = File.read!("./priv/pkey.pem")
    raw_root = File.read!("./priv/AppleRootCA-G3.cer")

    env = :erlang_apay_decrypt.prepare_env(raw_pkey, raw_root, 0)

    :erlang_apay_decrypt.verify_and_decrypt_apay_message(token, env: env, skip_chain_check: true)
    |> IO.inspect()

    assert false
  end
end
