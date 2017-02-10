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
  def keygen(p, q) do
    n = p * q
    e = 3
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

defmodule CubedRoot do
  # Cubed root dealing w/ float truncation from :math.pow
  def root(x) do
    guess = :math.pow(x, 1 / 3) |> round
    root(x, guess, guess * 2)
  end
  def root(x, low, high) do
    mid = low + div(high - low, 2)
    case mid * mid * mid do
      n when n == x -> mid
      n when n > x -> root(x, low, mid)
      n when n < x -> root(x, mid, high)
    end
  end
end

defmodule S4Ch40 do
  @secret "Excelsior!"
  def enc(pub), do: RSA.encrypts(pub, @secret)

  def check(msg), do: @secret == msg
end

# Intentionally smaller primes so that the mod matters during encryption.
# Otherwise the CRT continues to work, but is unnecessary.
{k1, _} = RSA.keygen(16714067792849807753, 15642976020000838319)
{k2, _} = RSA.keygen(16487628448435202783, 16921745212356004247)
{k3, _} = RSA.keygen(16552630569599308553, 15019430665694787833)

c1 = S4Ch40.enc(k1)
c2 = S4Ch40.enc(k2)
c3 = S4Ch40.enc(k3)

# IO.inspect [c1, c2, c3]

{3, n1} = k1
{3, n2} = k2
{3, n3} = k3

m_s_1 = n2 * n3
m_s_2 = n1 * n3
m_s_3 = n1 * n2

n_123 = n1 * n2 * n3

result = rem(c1 * m_s_1 * InvMod.invmod(m_s_1, n1) +
             c2 * m_s_2 * InvMod.invmod(m_s_2, n2) +
             c3 * m_s_3 * InvMod.invmod(m_s_3, n3),
             n_123)

result_msg = CubedRoot.root(result) |> Integer.digits(256) |> IO.iodata_to_binary
IO.inspect ["Found message:", S4Ch40.check(result_msg), result_msg]
