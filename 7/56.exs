defmodule RC4 do
  def enc(key, data), do: :crypto.stream_init(:rc4, key) |> :crypto.stream_encrypt(data) |> elem(1)
  def keystream(key, l), do: enc(key, String.duplicate(<<0>>, l))
  def rand_key, do: (for _ <- 1..16, do: :crypto.rand_uniform(1, 0xff))
end

defmodule Oracle do
  @secret "QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F"
  @cookie Base.decode64!(@secret)

  def rc4(request) do
    RC4.enc(RC4.rand_key, request <> @cookie)
  end

  def correct_cookie?(guess), do: guess == @cookie
end

defmodule Attack do
  use Bitwise

  @temp_dir "tmp/rc4-biases"
  @ctext_count 0xffffff

  File.mkdir_p(@temp_dir)

  def write_results(n \\ 0x4000000) do
    File.open(fname("16"), [:write, :append], fn(f16) ->
      File.open(fname("32"), [:write, :append], fn(f32) ->
        for _ <- 1..n do
          v = RC4.keystream(RC4.rand_key, 32)
          IO.puts(f16, :binary.at(v, 15))
          IO.puts(f32, :binary.last(v))
        end
      end)
    end)
  end

  def analyze_results(z) do
    File.stream!(fname(z))
    |> counts
    |> IO.inspect(limit: :infinity, pretty: true)
    |> pcts
    |> IO.inspect(limit: :infinity, pretty: true)
    |> Enum.sort_by(&(-elem(&1, 1)))
    |> IO.inspect(limit: :infinity, pretty: true)
    |> hd
    |> elem(0)
  end

  def solve(prefix \\ "", total \\ 16, accum \\ {"", ""})
  def solve(_prefix, 0, {a, b}), do: a <> b
  def solve(prefix, total, {a, b}) do
    [c16, c32] = ctext_vals(prefix)
    solve(prefix <> "A",
          total - 1,
          {<< c16 ^^^ 240 >> <> a, if(c32, do: << c32 ^^^ 224 >> <> b, else: b)})
  end

  defp ctext_vals(prefix) do
    ctext_counts(prefix)
    |> Enum.unzip
    |> Tuple.to_list
    |> Enum.map(&(counts(&1) |> pcts |> highest))
  end

  def ctext_counts(prefix) do
    path = fname("oracle-#{byte_size(prefix)}")

    unless File.exists?(path), do: write_ctext_vals(path, prefix)

    File.stream!(path)
    |> Stream.map(fn(l) ->
      case String.split(l, ",") do
        [c16, "\n"] -> {c16, nil}
        [c16, c32]  -> {c16, c32}
      end
    end)
  end

  def write_ctext_vals(path, prefix) do
    File.open(path, [:write, :append], fn(f) ->
      for _ <- 0..@ctext_count do
        ctext = Oracle.rc4(prefix)
        {c16, c32} = {:binary.at(ctext, 15),
                      (if byte_size(ctext) > 31, do: :binary.at(ctext, 31), else: nil)}
        IO.puts f, "#{c16},#{c32}"
      end
    end)
  end

  defp counts([nil | _]), do: {%{nil => 0}, 1}
  defp counts(vals) do
    Enum.reduce(vals, {%{}, 0},fn(v, {m, c}) ->
      {Map.put(m, v, (m[v] || 0) + 1), c + 1}
    end)
  end
  defp pcts({counts, total}) do
    Enum.reduce(counts, %{}, fn({k, v}, m) -> Map.put(m, parse_int(k), v / total) end)
  end
  defp highest(pcts), do: Enum.sort_by(pcts, &(-elem(&1, 1))) |> hd |> elem(0)

  def fname(z), do: "#{@temp_dir}/#{z}.txt"

  defp parse_int(nil), do: nil
  defp parse_int(i) when is_integer(i), do: i
  defp parse_int(s), do: Integer.parse(s) |> elem(0)
end

# Attack.write_results
# IO.inspect ["Most common for 16", Attack.analyze_results(16)]
# 240
# IO.inspect ["Most common for 32", Attack.analyze_results(32)]
# 224
# I guess the graphs in the paper were sufficient for that part...

IO.puts "Sit tight..."
IO.puts Attack.solve
