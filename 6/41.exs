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

  def encrypt({e, n}, m), do: :crypto.mod_pow(m, e, n) |> :crypto.bytes_to_integer
  def decrypt({d, n}, c) do
    :crypto.mod_pow(c, d, n) |> :crypto.bytes_to_integer
  end

  def encrypts(pub_key, msg), do: encrypt(pub_key, msg_to_int(msg))
  def decrypts({d, n}, c), do: :crypto.mod_pow(c, d, n)

  defp msg_to_int(msg), do: :crypto.bytes_to_integer(msg)
end

defmodule Server do
  @tab :ets.new(:server_hashes, [:set])
  @key RSA.keygen(65537,
                  95788282400026841675435085021830068475306523744137801501461562211907125998759,
                  107198165909420975001068753565629319931225058733897759186404620877780740694297)

  def dec(c) do
    unless seen?(c), do: RSA.decrypt(priv_key, c)
  end

  def pub_key, do: elem(@key, 0)

  defp priv_key, do: elem(@key, 1)

  defp seen?(c) do
    exists = !Enum.empty?(:ets.lookup(@tab, c))
    unless exists, do: :ets.insert(@tab, {c, true})
    exists
  end
end

defmodule Client do
  def last_message do
    msg = "#{:os.system_time(:seconds)}|this is the payload!"
    c = RSA.encrypts(Server.pub_key, msg)
    IO.inspect ["Client-Server echo correct", Server.dec(c) == :crypto.bytes_to_integer(msg)]
    c
  end
end

c = Client.last_message
IO.inspect ["Will server re-decrypt?", Server.dec(c)]

{e, n} = Server.pub_key
s = 42
c1 = :crypto.mod_pow(s, e, n) |> :crypto.bytes_to_integer
c1 = :crypto.mod_pow(c * c1, 1, n) |> :crypto.bytes_to_integer

p1 = Server.dec(c1)

p = rem(p1 * InvMod.invmod(s, n), n)
IO.inspect [p, Integer.digits(p, 256)]
