
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
  def keygen do
    p = 12901056913087924478007444146960867125242167487998903461385334029177746944717079159894587558791819221847068238004034831147907034746213683350590815683063509
    q = 11250981099238279525992566316704791285366815448617458346283266527764868719075816669056127782904475684300139188859903059602898526810307895057439100661084309
    n = p * q
    e = 3
    d = InvMod.invmod(e, (p - 1) * (q - 1))

    {{e, n}, {d, n}}
  end

  def encrypt({e, n}, m) do
    :crypto.mod_pow(m, e, n) |> :crypto.bytes_to_integer
  end

  def decrypt({d, n}, c) do
    :crypto.mod_pow(c, d, n) |> :crypto.bytes_to_integer
  end

  def encrypts(pub_key, msg), do: encrypt(pub_key, msg_to_int(msg))
  def decrypts({d, n}, c), do: :crypto.mod_pow(c, d, n)

  defp msg_to_int(msg), do: :crypto.bytes_to_integer(msg)
end

# IO.inspect ["Test egcd", {2, {-9, 47}} == InvMod.egcd(240, 46), InvMod.egcd(240, 46)]
# IO.inspect ["Test invmod", 1969 == InvMod.invmod(42, 2017), InvMod.invmod(42, 2017)]
# IO.inspect ["Test invmod", 2753 == InvMod.invmod(17, 3120), InvMod.invmod(17, 3120)]

{pub_key, private_key} = RSA.keygen

m = 0xfadfa092d
enc = RSA.encrypt(pub_key, m)
dec = RSA.decrypt(private_key, enc)
IO.inspect ["Test encrypt/decrypt num:", m == dec, m, dec]

msg = "this is the message with the words involving cats"
enc = RSA.encrypts(pub_key, msg)
dec = RSA.decrypts(private_key, enc)
IO.inspect ["Test encrypt/decrypt msg:", msg == dec, dec]
