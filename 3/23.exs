use Bitwise

defmodule MT19937 do
  @w 32
  @n 624

  @low_bits 0xFFFFFFFF

  def seed(n) do
    Process.put(:mt19937_idx, @n)
    Process.put(:mt19937_series, gen_series(n))
  end

  def rand do
    if Process.get(:mt19937_idx) >= @n, do: twist

    idx = Process.get(:mt19937_idx)
    num = elem(Process.get(:mt19937_series), idx)
    num = num ^^^ (num >>> 11)
    num = num ^^^ ((num <<< 7) &&& 0x9D2C5680)
    num = num ^^^ ((num <<< 15) &&& 0xEFC60000)
    num = num ^^^ (num >>> 18)

    Process.put(:mt19937_idx, idx + 1)

    num &&& @low_bits
  end

  defp twist do
    new_mt = Enum.reduce(0..(@n - 1), Process.get(:mt19937_series), fn(i, mt) ->
      x = (elem(mt, i) &&& 0x80000000) + (elem(mt, rem(i + 1, @n)) &&& 0x7fffffff)
      xA = x >>> 1
      xA = if rem(x, 2) != 0, do: xA ^^^ 0x9908B0DF, else: xA

      put_elem(mt, i, elem(mt, rem(i + 397, @n)) ^^^ xA)
    end)

    Process.put(:mt19937_series, new_mt)
    Process.put(:mt19937_idx, 0)
  end

  defp gen_series(first), do: List.to_tuple([first | gen_series(first, 1)])
  defp gen_series(_prev, @n), do: []
  defp gen_series(prev, idx) do
    num = @low_bits &&& ((1812433253 * (prev ^^^ (prev >>> 30))) + idx)
    [num | gen_series(num, idx + 1)]
  end
end

defmodule S3Ch23 do
  @seed :rand.uniform(0xffffffff)

  MT19937.seed(@seed)

  def seed, do: @seed

  def replace_mt(mt) do
    Process.put(:mt19937_series, mt)
    Process.put(:mt19937_idx, 624)
  end

  def reverse_temper(num) do
    num
    |> reverse_temper_right(18)
    |> reverse_temper_left(15, 0xEFC60000)
    |> reverse_temper_left(7, 0x9D2C5680)
    |> reverse_temper_right(11)
  end

  def reverse_temper_right(n, shift) do
    bits = Integer.digits(n, 2) |> List.to_tuple
    len = tuple_size(bits)

    Enum.reduce(0..(len - 1), bits, fn(idx, bs) ->
      if idx >= shift do
        put_elem(bs, idx, elem(bs, idx) ^^^ elem(bs, idx - shift))
      else
        bs
      end
    end)
    |> Tuple.to_list
    |> Integer.undigits(2)
  end

  def reverse_temper_left(n, shift, magic) do
    mag_bits = pad_digs(magic, 32)
    bits = pad_digs(n, 32)

    Enum.reduce(31..0, bits, fn(idx, bs) ->
      if idx <= (32 - shift - 1) do
        b = elem(bs, idx)
        orbit = elem(bs, idx + shift)
        mbit = elem(mag_bits, idx)

        put_elem(bs, idx, (orbit &&& mbit) ^^^ b)
      else
        bs
      end
    end)
    |> Tuple.to_list
    |> Integer.undigits(2)
  end

  def pad_digs(n, l) do
    digs = Integer.digits(n, 2)
    pad = if length(digs) < l, do: (for _ <- (0..(l - length(digs) - 1)), do: 0), else: []
    List.to_tuple(pad ++ digs)
  end
end


# num = 0xabcd1234
# tempered = (num >>> 11) ^^^ num
# untemped = S3Ch23.reverse_temper_right(tempered, 11)
# IO.inspect [num, tempered, untemped]

# num = 0xf1230945
# tempered = num ^^^ ((num <<< 7) &&& 0x9D2C5680)
# untemped = S3Ch23.reverse_temper_left(tempered, 7, 0x9D2C5680)
# IO.inspect [num, tempered, untemped]

# rand = MT19937.rand
# mt_elem = elem(Process.get(:mt19937_series), 0)
# IO.inspect [rand, mt_elem, S3Ch23.reverse_temper(rand)]

first_624 = for _ <- 0..623, do: MT19937.rand()
# IO.inspect first_624
next_1000  = for _ <- 0..623, do: MT19937.rand()
# IO.inspect next_624

Enum.map(first_624, &S3Ch23.reverse_temper/1) |> List.to_tuple |> S3Ch23.replace_mt

expected_next_1000 = for _ <- 0..623, do: MT19937.rand
# IO.inspect expected_next_624

IO.inspect ['all eql',
            Enum.zip(expected_next_1000, next_1000) |> Enum.all?(fn({a, b}) -> a == b end)]

