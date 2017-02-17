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

    Process.put(:leaked_k, k)

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

  def recover_key(k, msg, {r, s}), do: mod(((s * k) - hash(msg)) * InvMod.invmod(r, q), q)

  defp modpow(base, pow, mod), do: :crypto.mod_pow(base, pow, mod) |> :crypto.bytes_to_integer
  defp mod(n, mod), do: modpow(n, 1, mod)
end

# msg = "this is fun to sign!"
# {priv_key, pub_key} = DSA.gen_keys
# sig = DSA.sign(priv_key, msg)
# IO.inspect ['Verify', DSA.verify(pub_key, msg, sig)]
# IO.inspect ['Should not verify', DSA.verify(pub_key, msg <> "!", sig)]
# IO.inspect ['Reover key from k', priv_key == DSA.recover_key(Process.get(:leaked_k), msg, sig)]

pub_key = "084ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4
           abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004
           e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed
           1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b
           bb283e6633451e535c45513b2d33c99ea17"
           |> Util.hex_to_int

msg = "For those that envy a MC it can be hazardous to your health
So be friendly, a matter of life and death, just like a etch-a-sketch
"

IO.inspect ['Correct msg fingerprint:',
            DSA.hash(msg),
            DSA.hash(msg) |> Util.int_to_hex,
            DSA.hash(msg) == 0xd2d0714f014a9784047eaeccf956520045c45265]

r = 548099063082341131477253921760299949438196259240
s = 857042759984254168557880549501802188789837994940
sig = {r, s}

key_fp = "0954edd5e0afe5542a4adf012611a91912a3ec16"

IO.inspect ["Pub works:", DSA.verify(pub_key, msg, sig)]

found_k = Enum.find 1..165536, fn (n) ->
  x = DSA.recover_key(n, msg, sig)
  sig == DSA.sign(x, msg, n)
end

if found_k do
  found_key = DSA.recover_key(found_k, msg, sig)
  found_key_fp = Util.sha1_int(found_key)
  IO.inspect ['Found key:', found_key, found_key_fp]
  IO.inspect ['Check found key fp:', key_fp == found_key_fp]
else
  IO.puts "No key found!"
end
