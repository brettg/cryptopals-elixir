
:application.start(:inets)

defmodule S4C31 do
  @user_agent 'S4C31'
  @base_url 'http://localhost:4000/?file='
  @sig_len 20

  def try(filename, signature) do
    {time, {:ok, {{_, code, _}, _, _}}} = :timer.tc(S4C31, :req, [filename, signature])
    {code == 200, time}
  end

  def req(filename, signature) do
    url = @base_url ++ filename ++ '&signature=' ++ signature
    :httpc.request(:get, {url, [{'User-Agent', @user_agent}]}, [], [])
  end

  def guess_byte(filename, guess, offset), do: guess_byte(filename, guess, offset, 0, 0, 0)
  def guess_byte(filename, guess, offset, n, best, best_time) do
    guess = List.replace_at(guess, offset, n)
    sig = encode_sig(guess)
    {success, time} = S4C31.try(filename, sig)

    if success do
      n
    else
      {best, best_time} = if time > best_time, do: {n, time}, else: {best, best_time}

      if n == 255 do
        best
      else
        guess_byte(filename, guess, offset, n + 1, best, best_time)
      end
    end
  end

  def solve(filename) do
    guess = for _ <- 1..@sig_len, do: 0
    try(filename, guess)
    solve(filename, guess, 0)
  end
  def solve(filename, guess, offset) do
    byte = guess_byte(filename, guess, offset)
    new_guess = List.replace_at(guess, offset, byte)
    if offset == @sig_len - 1 do
      new_guess
    else
      solve(filename, new_guess, offset + 1)
    end
  end

  def encode_sig(signature_bytes) do
    # Round about but works..
    signature_bytes
    |> IO.iodata_to_binary
    |> Base.encode16
    |> :binary.bin_to_list
  end
end

filename = 'cats'
sig = S4C31.solve(filename)
IO.inspect [filename,
            S4C31.encode_sig(sig),
            S4C31.try(filename, sig)]
