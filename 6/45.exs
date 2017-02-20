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
Process.put :dsa_g, Util.hex_to_int("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119
                                     458fef538b8fa4046c8db53039db620c094c9fa077ef389b5
                                     322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047
                                     0f5b64c36b625a097f1651fe775323556fe00b3608c887892
                                     878480e99041be601a62166ca6894bdd41a7054ec89f756ba
                                     9fc95302291")

defmodule DSA do
  @p "800000000000000089e1855218a0e7dac38136ffafa72eda7
      859f2171e25e65eac698c1702578b07dc2a1076da241c76c6
      2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe
      ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2
      b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87
      1a584471bb1"
     |> Util.hex_to_int

  @q "f4f47f05794b256174bba6e9b396a7707e563c5b" |> Util.hex_to_int

  def p, do: @p
  def q, do: @q
  def g, do: Process.get(:dsa_g)

  def set_g(new_g), do: Process.put(:dsa_g, new_g)

  def gen_keys do
    secret = :crypto.rand_uniform(0, q)
    {secret, modpow(g, secret, p)}
  end

  def sign(private_key, msg), do: sign(private_key, msg, :crypto.rand_uniform(1, q))
  def sign(private_key, msg, k) do
    r = rem(modpow(g, k, p), q)
    s = rem((hash(msg) + private_key * r) * InvMod.invmod(k, q), q)
    {r, s}
  end

  def verify(pub_key, msg, {r, s}) do
    w = rem(InvMod.invmod(s, q), q)
    u1 = rem(hash(msg) * w, q)
    u2 = rem(r * w, q)
    v = rem(rem(modpow(g, u1, p) * modpow(pub_key, u2, p), p), q)
    v == r
  end

  def g1_magic_sig(y) do
    r = mod(modpow(y, 101, p), q)
    s = mod(r * InvMod.invmod(101, q), q)
    {r, s}
  end 
  def hash(msg), do: :crypto.hash(:sha, msg) |> :crypto.bytes_to_integer
  defp modpow(base, pow, mod), do: :crypto.mod_pow(base, pow, mod) |> :crypto.bytes_to_integer
  defp mod(n, mod), do: modpow(n, 1, mod)
end


DSA.set_g(0)
{private_key, pub_key} = DSA.gen_keys

# IO.inspect [private_key, pub_key]
IO.puts "0 public key for g = 0:"
IO.inspect DSA.verify(0, "abc", DSA.sign(private_key, "abc"))
IO.inspect DSA.verify(0, "def", DSA.sign(private_key, "abc"))

DSA.set_g(DSA.p + 1)
{private_key, pub_key} = DSA.gen_keys

# IO.inspect [private_key, pub_key]
IO.puts "1 public key for g = p + 1:"
IO.inspect DSA.verify(1, "abc", DSA.sign(private_key, "abc"))
IO.inspect DSA.verify(1, "def", DSA.sign(private_key, "abc"))

for _ <- 1..3 do
  pub_key = :crypto.rand_uniform(1, DSA.p)
  magic_sig = DSA.g1_magic_sig(pub_key)
  IO.puts "Magic Sig for g = p + 1, public key = #{pub_key}:"
  IO.inspect DSA.verify(pub_key, "Hello World", magic_sig)
  IO.inspect DSA.verify(pub_key, "Goodbye, world", magic_sig)
end
