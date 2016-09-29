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

defmodule S3Ch22 do

  def some_rand do
    rand_sleep(40, 1000)
    MT19937.seed(unix_now)
    rand_sleep(40, 1000)
    MT19937.rand
  end

  def rand_sleep(min_sec, max_sec) do
    :timer.sleep(min_sec * 1000 + :rand.uniform((max_sec - min_sec) * 1000))
  end

  def unix_now do
    DateTime.to_unix(DateTime.utc_now)
  end
end

before = S3Ch22.unix_now
out = S3Ch22.some_rand
end_t = S3Ch22.unix_now

IO.puts "Checking. Started at #{before}. Ended at #{end_t}. Took #{end_t - before}s."

for n <- before..end_t do
  MT19937.seed(n)
  if MT19937.rand == out, do: IO.puts "It was #{n}."
end
