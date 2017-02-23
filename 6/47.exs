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
    if m > n, do: raise "Message too big!"
    mod_pow(m, e, n)
  end
  def decrypt({d, n}, c), do: mod_pow(c, d, n)

  def encrypts(pub_key, msg), do: encrypt(pub_key, msg_to_int(msg))
  def decrypts({d, n}, c), do: :crypto.mod_pow(c, d, n)

  def msg_to_int(msg), do: :crypto.bytes_to_integer(msg)
  def int_to_msg(int, len) do
    msg = Integer.digits(int, 256) |> IO.iodata_to_binary
    if byte_size(msg) < len, do: zero_bytes(len - byte_size(msg)) <> msg, else: msg
  end

  def mod_pow(b, e, m), do: :crypto.mod_pow(b, e, m) |> :crypto.bytes_to_integer

  def pkcs_pad(msg, len) do
    msg_len = byte_size(msg)
    if msg_len > len - 11, do: raise "Message to big for padding!"
    << 0, 2 >> <> rand_bytes(len - msg_len - 3) <> << 0 >> <> msg
  end
  def pkcs_unpad(<<0, 2>> <> rest), do: {:ok, String.split(rest, << 0 >>, parts: 2) |> List.last}
  def pkcs_unpad(_), do: {:error, "Invalid Padding"}

  def zero_bytes(n), do: (for _ <- 1..n, do: 0) |> IO.iodata_to_binary
  def rand_bytes(n), do: (for _ <- 1..n, do: :crypto.rand_uniform(1, 0xff)) |> IO.iodata_to_binary
end

defmodule Oracle do
  @key RSA.keygen(65537,
                  273723254066583931445307366284127539147,
                  276234454229463797840665822419125530619)
  @pub_key elem(@key, 0)
  @priv_key elem(@key, 1)

  @key_size Integer.digits(elem(@pub_key, 1), 256) |> length

  @msg "kick it, CC"
  @m RSA.pkcs_pad(@msg, @key_size) |> RSA.msg_to_int
  @c RSA.encrypt(@pub_key, @m)

  def c, do: @c
  def key_size, do: @key_size

  def pub_key, do: @pub_key
  defp priv_key, do: @priv_key

  def valid_pkcs?(c) do
    case RSA.decrypt(priv_key, c) |> RSA.int_to_msg(key_size) |> RSA.pkcs_unpad do
      {:ok, _} -> true
      {:error, _} -> false
    end
  end
end

defmodule S6Ch47 do
  @e elem(Oracle.pub_key, 0)
  @n elem(Oracle.pub_key, 1)
  @b RSA.mod_pow(2, (Oracle.key_size - 2) * 8, @n)

  def solve(c), do: solve(c, [(2 * @b)..(3 * @b - 1)], step_2a(c))
  def solve(_c, [a..a], _s), do: a
  def solve(c, ranges, s) do
    # IO.inspect [c,
    #             Enum.map(ranges, fn(a..b) -> {a..b, b - a} end),
    #             s]

    if length(ranges) > 1 do
      new_s = next_valid(c, s + 1)
      solve(c, step_3(ranges, new_s), new_s)
    else
      new_s = step_2c(c, hd(ranges), s)
      new_ranges = step_3(ranges, new_s)
      solve(c, new_ranges, new_s)
    end
  end

  def step_2a(c), do: next_valid(c, div(@n, 3 * @b))

  def next_valid(c, n) do
    if c_for_s(c, n) |> Oracle.valid_pkcs?, do: n, else: next_valid(c, n + 1)
  end

  def step_2c(c, a..b, s), do: step_2cr(c, a..b, 2 * div((b * s) - (2 * @b), @n))

  def step_2cr(c, a..b, r) do
    min_s = div((2 * @b) + (r * @n), b)
    max_s = div((3 * @b) + (r * @n), a)
    step_2cr(c, a..b, r, min_s, max_s)
  end
  def step_2cr(c, range, _r, s, max_s) when s >= max_s, do: step_2c(c, range, s)
  def step_2cr(c, a..b, r, s, max_s) do
    if c_for_s(c, s) |> Oracle.valid_pkcs? do
      s
    else
      step_2cr(c, a..b, r, s + 1, max_s)
    end
  end

  def step_3(ranges, s) do
    Enum.flat_map(ranges, fn(a..b) ->
      r_min = div((a * s) - (3 * @b) + 1, @n)
      r_max = div((b * s) - (2 * @b), @n)
      for r <- r_min..r_max do
        Enum.max([a, divceil((2 * @b) + (r * @n), s)])..
          Enum.min([b, div((3 * @b) - 1 + (r * @n), s)])
      end
    end)
    |> Enum.filter(fn(a..b) -> b >= a end)
    |> Enum.sort
    |> merge_ranges
  end

  def divceil(n, d) do
    div(n, d) + (if rem(n, d) == 0, do: 0, else: 1)
  end

  def merge_ranges(ranges) when length(ranges) < 2, do: ranges
  def merge_ranges([range]), do: [range]
  def merge_ranges([a1..b1, a2..b2 | rest]) do
    if b1 >= a2 do
      merge_ranges([a1..b2 | rest])
    else
      [a1..b1 | merge_ranges([a2..b2 | rest])]
    end
  end

  defp c_for_s(c, s), do: RSA.mod_pow(c * RSA.mod_pow(s, @e, @n), 1, @n)
end

solution = S6Ch47.solve(Oracle.c)
IO.inspect ["Found solution:",
            solution,
            RSA.int_to_msg(solution, Oracle.key_size) |> RSA.pkcs_unpad]

