defmodule InvMod do
  # returns {gcd, {Bézout coefficient x, Bézout coefficient y}}
  def egcd(a, b), do: egcd(a, b, 1, 0, 0, 1)
  def egcd(prev_r, 0, prev_s, _, prev_t, _), do: {prev_r, {prev_s, prev_t}}
  def egcd(prev_r, r, prev_s, s, prev_t, t) do
    q = div(prev_r, r)
    egcd(r, prev_r - q * r, s, prev_s - q * s, t, prev_t - q * t)
  end

  def invmod(a, m) do
    case egcd(a, m) do
      {1, {x, _}} -> rem(x + m, m)
      _ -> nil
    end
  end
end

defmodule RSA do
  def keygen(e, p, q) do
    n = p * q
    d = InvMod.invmod(e, (p - 1) * (q - 1))

    {{e, n}, {d, n}}
  end

  def encrypt({e, n}, msg), do: :crypto.mod_pow(msg_to_int(msg), e, n)
  def decrypt({d, n}, ctext), do: msg_to_int(ctext) |> :crypto.mod_pow(d, n)

  def msg_to_int(msg), do: :crypto.bytes_to_integer(msg)
  def int_to_msg(int), do: Integer.digits(int, 256) |> IO.iodata_to_binary
end

defmodule CubedRoot do
  # Cubed root dealing w/ float truncation from :math.pow
  # {exact, n}
  def root(x) do
    guess = :math.pow(x, 1 / 3) |> round
    root(x, guess, guess * 2)
  end

  def root(x, low, high) when high - low < 2 do
    cond do
      x == low * low * low -> {true, low}
      x == high * high * high -> {true, high}
      true -> {false, low}
    end
  end
  def root(x, low, high) do
    mid = low + div(high - low, 2)
    case mid * mid * mid do
      n when n == x -> {true, mid}
      n when n > x -> root(x, low, mid)
      n when n < x -> root(x, mid, high)
    end
  end
end

defmodule S6Ch42 do
  @keys RSA.keygen(3,
                   11389148028521709245677659574836820267724578887199464185288476984500128323653604877003542751455653717044194553249644399955297691444140326681011290795208857,
                   11386957510537681585242643195586856644210651200870975642065528202806258843559280262560502008999631784783895748059964620412278790014513565907922770834739663)

  @sha_asn_prefix <<0x30, 0x21, 0x30, 0x09,
                    0x06, 0x05, 0x2b, 0x0e, 0x02, 0x01, 0x1a,
                    0x05, 0x00,
                    0x04, 0x20>>

  def verify(msg, sig), do: (RSA.encrypt(pub_key, sig) |> unpad) == hash(msg)

  def sign(msg), do: RSA.decrypt(priv_key, pad_hash(hash(msg)))

  def asn1_encode(hash), do: @sha_asn_prefix <> hash

  def pub_key, do: elem(@keys, 0)
  defp priv_key, do: elem(@keys, 1)

  defp pad_hash(hash) do
    padding = const_bytes(128 - byte_size(hash) - 3 - byte_size(@sha_asn_prefix), 0xff)
    <<0, 1>> <> padding <> <<0>> <> asn1_encode(hash)
  end

  defp hash(msg), do: :crypto.hash(:sha, msg)

  def unpad(padded) do
    # RSA.int_to_msg removes the first 0
    << 1 >> <> padded = padded

    String.split(padded, << 0xff, 0>> <> @sha_asn_prefix, size: 2)
    |> List.last
    |> String.slice(0..19)
  end

  def const_bytes(n, byte), do: (for _ <- 1..n, do: byte) |> IO.iodata_to_binary
end

msg = "hi mom"

# {pub, priv} = RSA.keygen(3,
#                          11389148028521709245677659574836820267724578887199464185288476984500128323653604877003542751455653717044194553249644399955297691444140326681011290795208857,
#                          11386957510537681585242643195586856644210651200870975642065528202806258843559280262560502008999631784783895748059964620412278790014513565907922770834739663)
# IO.inspect ["Test RSA", RSA.decrypt(priv, RSA.encrypt(pub, "the RSA impl still works!!!"))]

IO.inspect ["Veryify Real Signature:", S6Ch42.verify(msg, S6Ch42.sign(msg))]

hsh = :crypto.hash(:sha, msg)

base = << 0, 1, 0xff, 0 >> <> S6Ch42.asn1_encode(hsh)
full = base <> S6Ch42.const_bytes(128 - byte_size(base), 0)

{exact, root} = (RSA.msg_to_int(full) |> CubedRoot.root)
c = if exact, do: 0, else: root + 1
missing_len = ((c * c * c) - (root * root * root)) |> RSA.int_to_msg |> byte_size
if missing_len < 128 - byte_size(base) do
  IO.inspect ["Verify forged", S6Ch42.verify(msg, RSA.int_to_msg(c))]
else
  IO.puts "Hmmmmm."
end
