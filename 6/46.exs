require Integer

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

  def encrypt({e, n}, m) do
    if m > n, do: raise "Message too big!."
    mod_pow(m, e, n)
  end
  def decrypt({d, n}, c), do: mod_pow(c, d, n)

  def encrypts(pub_key, msg), do: encrypt(pub_key, msg_to_int(msg))
  def decrypts({d, n}, c), do: :crypto.mod_pow(c, d, n)

  def msg_to_int(msg), do: :crypto.bytes_to_integer(msg)
  def int_to_msg(int), do: Integer.digits(int, 256) |> IO.iodata_to_binary

  def mod_pow(b, e, m), do: :crypto.mod_pow(b, e, m) |> :crypto.bytes_to_integer
end

defmodule Oracle do
  @key RSA.keygen(65537,
                  11125056204597511581303752178669423270128509718904842811394400941710343412916814768030655530551547659005463397283347528973278865192506762126162751604764969,
                  13212680235064253087623101527394086390475655371483067479464031316706210186024316263806732760504270262909231271046971643940037382512170490204850550717645497)

  def pub_key, do: elem(@key, 0)
  defp priv_key, do: elem(@key, 1)

  def p_even?(c), do: RSA.decrypt(priv_key, c) |> Integer.is_even
end

defmodule S6Ch46 do
  @secret "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="
          |> Base.decode64!

  @c RSA.encrypts(Oracle.pub_key, @secret)

  def solve, do: solve(@c, RSA.encrypt(Oracle.pub_key, 2), 0, n)
  def solve(_, _, min, max) when abs(max - min) < 2, do: fix_close(min, @c)
  def solve(c, factor, min, max) do
    print(max)

    new_c = RSA.mod_pow(c * factor, 1, n)

    mid = min + div(max - min, 2)
    {new_min, new_max} = if Oracle.p_even?(new_c), do: {min, mid}, else: {mid + 1, max}

    solve(new_c, factor, new_min, new_max)
  end

  def fix_close(m, c) do
    Enum.map(-1000..1000, &(&1 + m))
    |> Enum.find(fn(n) ->
      RSA.encrypt(Oracle.pub_key, n) == c
    end)
  end

  def print(max) do
    Integer.digits(max, 256)
    |> Enum.each(fn(n)->
      s = <<n>>
      if String.printable?(s), do: IO.write(s), else: IO.write("_")
    end)

    IO.write "\n"
  end

  defp n, do: elem(Oracle.pub_key, 1)
end

S6Ch46.print(S6Ch46.solve)
