defmodule Util do
  def hex_to_int(h) do
    h
    |> String.replace(~r/\s+/, "")
    |> Base.decode16!(case: :mixed)
    |> :crypto.bytes_to_integer
  end

  def int_to_hex(i) do
    i
    |> Integer.digits(256)
    |> IO.iodata_to_binary
    |> Base.encode16(case: :lower)
  end

  def sha1_int(i) do
    :crypto.hash(:sha, int_to_hex(i))
    |> Base.encode16(case: :lower)
  end
end

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

defmodule DSA do
  @p "800000000000000089e1855218a0e7dac38136ffafa72eda7
      859f2171e25e65eac698c1702578b07dc2a1076da241c76c6
      2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe
      ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2
      b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87
      1a584471bb1"
     |> Util.hex_to_int

  @q "f4f47f05794b256174bba6e9b396a7707e563c5b" |> Util.hex_to_int

  @g "5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119
      458fef538b8fa4046c8db53039db620c094c9fa077ef389b5
      322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047
      0f5b64c36b625a097f1651fe775323556fe00b3608c887892
      878480e99041be601a62166ca6894bdd41a7054ec89f756ba
      9fc95302291"
     |> Util.hex_to_int

  def p, do: @p
  def q, do: @q
  def g, do: @g

  def gen_keys do
    secret = :crypto.rand_uniform(0, q)
    {secret, modpow(g, secret, p)}
  end

  def sign(private_key, msg), do: sign(private_key, msg, :crypto.rand_uniform(1, q))
  def sign(private_key, msg, k) do
    r = rem(modpow(g, k, p), q)
    s = rem((hash(msg) + private_key * r) * InvMod.invmod(k, q), q)

    if r != 0 && s != 0 do
      {r, s}
    else
      sign(private_key, msg)
    end
  end

  def verify(pub_key, msg, {r, s}) do
    if r <= 0 || r >= q || s <= 0 || s >= q, do: raise "Bad Signature!"

    w = rem(InvMod.invmod(s, q), q)
    u1 = rem(hash(msg) * w, q)
    u2 = rem(r * w, q)
    v = rem(rem(modpow(g, u1, p) * modpow(pub_key, u2, p), p), q)
    v == r
  end

  def hash(msg), do: :crypto.hash(:sha, msg) |> :crypto.bytes_to_integer

  def shared_k(m1, s1, m2, s2) do
    # IO.inspect [m1, s1, m2, s2]
    mod(mod(m1 - m2, q) * InvMod.invmod(mod(s1 - s2, q), q), q)
  end
  def recover_key(k, msg, {r, s}), do: mod(((s * k) - hash(msg)) * InvMod.invmod(r, q), q)

  defp modpow(base, pow, mod), do: :crypto.mod_pow(base, pow, mod) |> :crypto.bytes_to_integer
  defp mod(n, mod), do: modpow(n, 1, mod)
end

sigs = File.read!("6/44.txt") |> String.split("\n") |> Enum.chunk(4) |> Enum.map(fn(parts) ->
  Enum.reduce(parts, %{}, fn(part, m) ->
    [k, v] = String.split(part, ": ")
    v = case k do
      "msg" -> v
      "m" -> Util.hex_to_int(if byte_size(v) == 40, do: v, else: "0" <> v)
      _ -> elem(Integer.parse(v), 0)
    end

    Map.put m, k, v
  end)
end)


key_fp = "ca8f6f7c66fa362d40760d135b763eb8527d3d52"

for sigA <- sigs, sigB <- sigs do
  if sigA["msg"] != sigB["msg"] do
    k = DSA.shared_k(sigA["m"], sigA["s"], sigB["m"], sigB["s"])
    sig = {sigA["r"], sigA["s"]}
    msg = sigA["msg"]
    key = DSA.recover_key(k, msg, sig)
    # IO.inspect [key, msg, k]
    if sig == DSA.sign(key, msg, k) do
      IO.inspect ['Found key:', 
                  key,
                  Util.sha1_int(key) == key_fp,
                  sigA["msg"], 
                  sigB["msg"]]
    end
  end
end
