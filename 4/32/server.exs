# To start run (in this directory):
# mix deps.get
# mix run --no-halt server.exs
#

defmodule CryptUtils do
  def rand_bytes(n), do: (for _ <- 1..n, do: :rand.uniform(0xff + 1) - 1) |> IO.iodata_to_binary
  def const_bytes(n, b), do: (for _ <- 1..n, do: b) |> IO.iodata_to_binary
end

defmodule HMACSha1 do
  use Bitwise

  @blocksize 64
  @o_const CryptUtils.const_bytes(@blocksize, 0x5c)
  @i_const CryptUtils.const_bytes(@blocksize, 0x36)

  # https://en.wikipedia.org/wiki/Hash-based_message_authentication_code#Implementation
  def hmac(key, msg) do
    key = key |> trunc_key |> pad_key

    o_pad = bin_xor(@o_const, key)
    i_pad = bin_xor(@i_const, key)

    hash(o_pad <> hash(i_pad <> msg))
  end

  defp hash(l) do
    :crypto.hash(:sha, l)
  end

  defp bin_xor(a, b), do: bin_xor(a, b, "")
  defp bin_xor("", "", acc), do: acc
  defp bin_xor(<<a, as::binary>>, <<b, bs::binary>>, acc) do
    bin_xor(as, bs, <<acc::binary, a ^^^ b>>)
  end

  defp trunc_key(key) when byte_size(key) <= @blocksize, do: key
  defp trunc_key(key), do: hash(key)

  defp pad_key(key) when byte_size(key) == @blocksize, do: key
  defp pad_key(key) do
    key <> ((for _ <- 1..(@blocksize - byte_size(key)), do: 0) |> IO.iodata_to_binary)
  end
end

defmodule S4Ch32Server do
  import Plug.Conn

  @secret CryptUtils.rand_bytes(16)

  def init(options) do
    options
  end

  def call(conn, _opts) do
    params = fetch_query_params(conn).query_params
    file = params["file"]
    sig = params["signature"]

    put_resp_content_type(conn, "text/plain")

    if conn.request_path == "/cheat" do
      send_resp(conn, 200, file |> sig_for_file |> Base.encode16)
    else
      valid = valid?(file, sig)
      IO.puts "Valid: #{valid} File: #{file} Signature: #{sig}"

      if valid, do: send_resp(conn, 200, "Good!"), else: send_resp(conn, 500, "Bad!")
    end
  end

  defp sig_for_file(file) do
    HMACSha1.hmac(@secret, file)
  end

  defp valid?(file, sig) when is_nil(file) or is_nil(sig), do: false
  defp valid?(file, sig) do
    case Base.decode16(sig) do
      {:ok, decoded} -> insecure_compare(sig_for_file(file), decoded)
      :error -> false
    end
  end

  defp insecure_compare(sigA, sigB) when byte_size(sigA) != byte_size(sigB), do: false
  defp insecure_compare(sigA, sigB) do
    Enum.zip(:binary.bin_to_list(sigA), :binary.bin_to_list(sigB))
    |> Enum.with_index
    |> Enum.all?(fn ({{a, b}, idx})->
      if idx > 0, do: :timer.sleep(5)
      a == b
    end)
  end
end

{:ok, _} = Plug.Adapters.Cowboy.http S4Ch32Server, []
