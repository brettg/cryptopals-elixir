Process.put(:md4, 0)
defmodule MD4 do
  use Bitwise

  @a 0x67452301
  @b 0xefcdab89
  @c 0x98badcfe
  @d 0x10325476
  @init {@a, @b, @c, @d}

  @mask 0xffffffff

  @round_1 [
    [{0,  3}, {1,  7}, {2,  11}, {3,  19}],
    [{4,  3}, {5,  7}, {6,  11}, {7,  19}],
    [{8,  3}, {9,  7}, {10, 11}, {11, 19}],
    [{12, 3}, {13, 7}, {14, 11}, {15, 19}]
  ]

  @round_2 [
    [{0, 3}, {4, 5}, {8,  9}, {12, 13}],
    [{1, 3}, {5, 5}, {9,  9}, {13, 13}],
    [{2, 3}, {6, 5}, {10, 9}, {14, 13}],
    [{3, 3}, {7, 5}, {11, 9}, {15, 13}]
  ]

  @round_3 [
    [{0, 3}, {8,  9}, {4,11}, {12, 15}],
    [{2, 3}, {10, 9}, {6,11}, {14, 15}],
    [{1, 3}, {9,  9}, {5,11}, {13, 15}],
    [{3, 3}, {11, 9}, {7,11}, {15, 15}]
  ]

  def init, do: @init
  def round_1, do: @round_1
  def round_2, do: @round_2
  def round_3, do: @round_3

  def hash(msg) when is_binary(msg), do: :binary.bin_to_list(msg) |> hash
  def hash(msg) do
    Process.put(:md4, Process.get(:md4) + 1)

    pad(msg)
    |> Enum.chunk(64)
    |> Enum.reduce(init, &hash_block/2)
    |> Tuple.to_list
    |> unsplit_words
  end

  def pad(msg) do
    len = length(msg)
    idx = rem(len, 64)
    zero_c = if idx < 56, do: 55 - idx,  else: 119 - idx
    len_part = le_bytes(len * 8, 8)
    msg ++ [0x80] ++ zeros(zero_c) ++ len_part
  end

  def hash_block(blk, {aa, bb, cc, dd}) do
    {{a, b, c, d}, _} = Enum.reduce(all_steps,
                                    {{aa, bb, cc, dd}, split_words(blk)},
                                    &compress_step/2)
    {(a + aa) &&& @mask, (b + bb) &&& @mask, (c + cc) &&& @mask, (d + dd) &&& @mask}
  end

  def all_steps do
    Enum.zip(@round_1, [&ff/7, &ff/7, &ff/7, &ff/7]) ++
    Enum.zip(@round_2, [&gg/7, &gg/7, &gg/7, &gg/7]) ++
    Enum.zip(@round_3, [&hh/7, &hh/7, &hh/7, &hh/7])
  end

  def compress_step({consts, func}, {{a, b, c, d}, words}) do
    [{i1, s1}, {i2, s2}, {i3, s3}, {i4, s4}] = consts

    a = func.(a, b, c, d, i1, s1, words)
    d = func.(d, a, b, c, i2, s2, words)
    c = func.(c, d, a, b, i3, s3, words)
    b = func.(b, c, d, a, i4, s4, words)

    {{a, b, c, d}, words}
  end

  def f(x, y, z), do: (x &&& y) ||| ((x ^^^ @mask) &&& z)
  def g(x, y, z), do: (x &&& y) ||| (x &&& z) ||| (y &&& z)
  def h(x, y, z), do: x ^^^ y ^^^ z

  def ff(a, b, c, d, k, s, m), do: (a + f(b, c, d) + Enum.at(m, k)) |> lrot(s)
  def gg(a, b, c, d, k, s, m), do: (a + g(b, c, d) + Enum.at(m, k) + 0x5a827999) |> lrot(s)
  def hh(a, b, c, d, k, s, m), do: (a + h(b, c, d) + Enum.at(m, k) + 0x6ed9eba1) |> lrot(s)

  def lrot(n, s), do: ((n <<< s) &&& @mask) ||| ((n &&& @mask) >>> (32 - s))

  def le_bytes_to_int(l), do: Enum.reverse(l) |> Integer.undigits(256)

  def bytes(n, size \\ 4) do
    b = Integer.digits(n, 256)
    zeros(size - length(b)) ++ b
  end
  def le_bytes(n, size \\ 4), do: bytes(n, size) |> Enum.reverse

  def split_words(blk), do: Enum.chunk(blk, 4) |> Enum.map(&le_bytes_to_int/1)
  def unsplit_words(l), do: Enum.map(l, &le_bytes/1) |> List.flatten

  def zeros(0), do: []
  def zeros(n), do: (for _ <- 1..n, do: 0)
end

Process.put(:ms, 0)
defmodule Attack do
  use Bitwise
  @mask 0xffffffff

  @fixes_1 [
    {{1, :a, 6}, {0, :b, 6}},

    {{1, :d, 6}, 0},
    {{1, :d, 7}, {1, :a, 7}},
    {{1, :d, 10}, {1, :a, 10}},

    {{1, :c, 6}, 1},
    {{1, :c, 7}, 1},
    {{1, :c, 10}, 0},
    {{1, :c, 25}, {1, :d, 25}},

    {{1, :b, 6}, 1},
    {{1, :b, 7}, 0},
    {{1, :b, 10}, 0},
    {{1, :b, 25}, 0},

    {{2, :a, 7}, 1},
    {{2, :a, 10}, 1},
    {{2, :a, 25}, 0},
    {{2, :a, 13}, {1, :b, 13}},

    {{2, :d, 13}, 0},
    {{2, :d, 18}, {2, :a, 18}},
    {{2, :d, 19}, {2, :a, 19}},
    {{2, :d, 20}, {2, :a, 20}},
    {{2, :d, 21}, {2, :a, 21}},
    {{2, :d, 25}, 1},

    {{2, :c, 12}, {2, :d, 12}},
    {{2, :c, 13}, 0},
    {{2, :c, 14}, {2, :d, 14}},
    {{2, :c, 18}, 0},
    {{2, :c, 19}, 0},
    {{2, :c, 20}, 1},
    {{2, :c, 21}, 0},

    {{2, :b, 12}, 1},
    {{2, :b, 13}, 1},
    {{2, :b, 14}, 0},
    {{2, :b, 16}, {2, :c, 16}},
    {{2, :b, 18}, 0},
    {{2, :b, 19}, 0},
    {{2, :b, 20}, 0},
    {{2, :b, 21}, 0},

    {{3, :a, 12}, 1},
    {{3, :a, 13}, 1},
    {{3, :a, 14}, 1},
    {{3, :a, 16}, 0},
    {{3, :a, 18}, 0},
    {{3, :a, 19}, 0},
    {{3, :a, 20}, 0},
    {{3, :a, 22}, {2, :b, 22}},
    {{3, :a, 21}, 1},
    {{3, :a, 25}, {2, :b, 25}},

    {{3, :d, 12}, 1},
    {{3, :d, 13}, 1},
    {{3, :d, 14}, 1},
    {{3, :d, 16}, 0},
    {{3, :d, 19}, 0},
    {{3, :d, 20}, 1},
    {{3, :d, 21}, 1},
    {{3, :d, 22}, 0},
    {{3, :d, 25}, 1},
    {{3, :d, 29}, {3, :a, 29}},

    {{3, :c, 16}, 1},
    {{3, :c, 19}, 0},
    {{3, :c, 20}, 0},
    {{3, :c, 21}, 0},
    {{3, :c, 22}, 0},
    {{3, :c, 25}, 0},
    {{3, :c, 29}, 1},
    {{3, :c, 31}, {3, :d, 31}},

    {{3, :b, 19}, 0},
    {{3, :b, 20}, 1},
    {{3, :b, 21}, 1},
    {{3, :b, 22}, 0},  # {{3, :b, 22}, {3, :c, 22}},
    {{3, :b, 25}, 1},
    {{3, :b, 29}, 0},
    {{3, :b, 31}, 0},

    {{4, :a, 22}, 0},
    {{4, :a, 25}, 0},
    {{4, :a, 26}, {3, :b, 26}},
    {{4, :a, 28}, {3, :b, 28}},
    {{4, :a, 29}, 1},
    {{4, :a, 31}, 0},

    {{4, :d, 22}, 0},
    {{4, :d, 25}, 0},
    {{4, :d, 26}, 1},
    {{4, :d, 28}, 1},
    {{4, :d, 29}, 0},
    {{4, :d, 31}, 1},

    {{4, :c, 18}, {4, :d, 18}},
    {{4, :c, 22}, 1},
    {{4, :c, 25}, 1},
    {{4, :c, 26}, 0},
    {{4, :c, 28}, 0},
    {{4, :c, 29}, 0},

    {{4, :b, 18}, 0},
    {{4, :b, 25}, 1}, # {{4, :b, 25}, {4, :c, 25}},
    {{4, :b, 26}, 1},
    {{4, :b, 28}, 1},
    {{4, :b, 29}, 0},
  ]
  @fixes_1_with_2_adjustments [
    {{1, :a, 6}, {0, :b, 6}},

    {{1, :d, 6}, 0},
    {{1, :d, 7}, {1, :a, 7}},
    {{1, :d, 10}, {1, :a, 10}},

    {{1, :c, 6}, 1},
    {{1, :c, 7}, 1},
    {{1, :c, 10}, 0},
    {{1, :c, 25}, {1, :d, 25}},

    {{1, :b, 6}, 1},
    {{1, :b, 7}, 0},
    {{1, :b, 10}, 0},
    {{1, :b, 25}, 0},

    {{2, :a, 7}, 1},
    {{2, :a, 10}, 1},
    {{2, :a, 16}, {1, :b, 16}}, # 2nd round
    {{2, :a, 17}, {1, :b, 17}}, # 2nd round
    {{2, :a, 19}, {1, :b, 19}}, # 2nd round
    {{2, :a, 22}, {1, :b, 22}}, # 2nd round
    {{2, :a, 25}, 0},
    {{2, :a, 13}, {1, :b, 13}},

    {{2, :d, 13}, 0},
    {{2, :d, 16}, 0}, # 2nd round
    {{2, :d, 17}, 0}, # 2nd round
    {{2, :d, 18}, {2, :a, 18}},
    {{2, :d, 19}, {2, :a, 19}},
    {{2, :d, 20}, {2, :a, 20}},
    {{2, :d, 21}, {2, :a, 21}},
    {{2, :d, 22}, 0}, # 2nd round
    {{2, :d, 25}, 1},

    {{2, :c, 12}, {2, :d, 12}},
    {{2, :c, 13}, 0},
    {{2, :c, 14}, {2, :d, 14}},
    {{2, :c, 16}, 0}, # 2nd round
    {{2, :c, 17}, 0}, # 2nd round
    {{2, :c, 18}, 0},
    {{2, :c, 19}, 0},
    {{2, :c, 20}, 1},
    {{2, :c, 21}, 0},
    {{2, :c, 22}, 0}, # 2nd round

    {{2, :b, 12}, 1},
    {{2, :b, 13}, 1},
    {{2, :b, 14}, 0},
    {{2, :b, 16}, 0}, # 2nd round  # {{2, :b, 16}, {2, :c, 16}},
    {{2, :b, 17}, 0}, # 2nd round
    {{2, :b, 18}, 0},
    {{2, :b, 19}, 0},
    {{2, :b, 20}, 0},
    {{2, :b, 21}, 0},
    {{2, :b, 22}, 0}, # 2nd round

    {{3, :a, 12}, 1},
    {{3, :a, 13}, 1},
    {{3, :a, 14}, 1},
    {{3, :a, 16}, 0},
    {{3, :a, 18}, 0},
    {{3, :a, 19}, 0},
    {{3, :a, 20}, 0},
    {{3, :a, 22}, {2, :b, 22}},
    {{3, :a, 21}, 1},
    {{3, :a, 25}, {2, :b, 25}},

    {{3, :d, 12}, 1},
    {{3, :d, 13}, 1},
    {{3, :d, 14}, 1},
    {{3, :d, 16}, 0},
    {{3, :d, 19}, 0},
    {{3, :d, 20}, 1},
    {{3, :d, 21}, 1},
    {{3, :d, 22}, 0},
    {{3, :d, 25}, 1},
    {{3, :d, 29}, {3, :a, 29}},

    {{3, :c, 16}, 1},
    {{3, :c, 19}, 0},
    {{3, :c, 20}, 0},
    {{3, :c, 21}, 0},
    {{3, :c, 22}, 0},
    {{3, :c, 25}, 0},
    {{3, :c, 29}, 1},
    {{3, :c, 31}, {3, :d, 31}},

    {{3, :b, 19}, 0},
    {{3, :b, 20}, 1},
    {{3, :b, 21}, 1},
    {{3, :b, 22}, 0},  # {{3, :b, 22}, {3, :c, 22}},
    {{3, :b, 25}, 1},
    {{3, :b, 29}, 0},
    {{3, :b, 31}, 0},

    {{4, :a, 22}, 0},
    {{4, :a, 25}, 0},
    {{4, :a, 26}, {3, :b, 26}},
    {{4, :a, 28}, {3, :b, 28}},
    {{4, :a, 29}, 1},
    {{4, :a, 31}, 0},

    {{4, :d, 22}, 0},
    {{4, :d, 25}, 0},
    {{4, :d, 26}, 1},
    {{4, :d, 28}, 1},
    {{4, :d, 29}, 0},
    {{4, :d, 31}, 1},

    {{4, :c, 18}, {4, :d, 18}},
    {{4, :c, 22}, 1},
    {{4, :c, 25}, 1},
    {{4, :c, 26}, 0},
    {{4, :c, 28}, 0},
    {{4, :c, 29}, 0},

    {{4, :b, 18}, 0},
    {{4, :b, 25}, 1}, # {{4, :b, 25}, {4, :c, 25}},
    {{4, :b, 26}, 1},
    {{4, :b, 28}, 1},
    {{4, :b, 29}, 0},
  ]

  @fixes_2 [
    {{5, :a, 18}, {4, :c, 18}},
    {{5, :a, 25}, 1},
    {{5, :a, 26}, 0},
    {{5, :a, 28}, 1},
    {{5, :a, 31}, 1},

    {{5, :d, 18}, {5, :a, 18}},
    {{5, :d, 25}, 1}, # {{5, :d, 25}, {4, :b, 25}},
    {{5, :d, 26}, 1}, # {{5, :d, 26}, {4, :b, 26}},
    {{5, :d, 28}, 1}, # {{5, :d, 28}, {4, :b, 28}},
    {{5, :d, 31}, {4, :b, 31}},

    {{5, :c, 25}, 1}, # {{5, :c, 25}, {5, :d, 25}},
    {{5, :c, 26}, 1}, # {{5, :c, 26}, {5, :d, 26}},
    {{5, :c, 28}, 1}, # {{5, :c, 28}, {5, :d, 28}},
    {{5, :c, 29}, {5, :d, 29}},
    {{5, :c, 31}, {5, :d, 31}},

    {{5, :b, 28}, {5, :c, 28}},
    {{5, :b, 29}, 1},
    {{5, :b, 31}, 0},

    {{6, :a, 28}, 1},
    {{6, :a, 31}, 1},

    {{6, :d, 28}, {5, :b, 28}},

    {{6, :c, 28}, {6, :d, 28}},
    {{6, :c, 29}, {6, :d, -29}},
    {{6, :c, 31}, {6, :d, -31}},
  ]

  @fixes_3 [
    {{9, :b, 31}, 1},
    {{10, :a, 31}, 1},
  ]

  # There wasn't much attempt # advantage to only randomizing the last two blocks...
  def find_collision do
    n = Process.get(:ms) + 1
    Process.put(:ms, n)
    if rem(n, 0x10000) == 0, do: IO.puts "Passed #{n} messages built"

    m = rand_m |> modify_m
    m2 = derive_m2(m)

    if m != m2 && MD4.hash(m) == MD4.hash(m2), do: [m, m2], else: find_collision
  end

  def derive_m2(m) do
    words = MD4.split_words(m)

    List.replace_at(words, 1, (Enum.at(words, 1) + 0x80000000) &&& @mask)
    |> List.replace_at(2,     (Enum.at(words, 2) + 0x70000000) &&& @mask)
    |> List.replace_at(12,    (Enum.at(words, 12) - 0x10000) &&& @mask)
    |> MD4.unsplit_words
  end

  def modify_m(msg) do
    MD4.split_words(msg)
    |> fix_first_round_with_second_adjustments
    |> fix_second_round
    |> MD4.unsplit_words
  end

  def fix_first_round(words), do: Enum.reduce(@fixes_1, words, &first_round_step_fix/2)
  def fix_first_round_with_second_adjustments(words) do
    Enum.reduce(@fixes_1_with_2_adjustments, words, &first_round_step_fix/2)
  end

  def fix_second_round(words) do
    (Enum.slice(@fixes_2, 0..8))
    |> Enum.reduce(words, &second_round_step_fix_a_reduce/2)
    |> second_round_step_fix_b({{5, :c, 25}, {5, :d, 25}})
    |> second_round_step_fix_b({{5, :c, 26}, {5, :d, 26}})
    |> second_round_step_fix_b({{5, :c, 31}, {5, :d, 31}})
    |> second_round_step_fix_a({{6, :d, 29}, {5, :b, 29}})
    |> second_round_step_fix_a({{6, :a, 28}, 1})
    |> second_round_step_fix_a({{6, :a, 31}, 1})
    |> second_round_step_fix_a({{6, :c, 28}, {6, :d, 28}})

    # |> second_round_step_fix_a({{5, :c, 28}, {5, :d, 28}}) # this breaks a2
  end

  def first_round_step_fix({{t_step, t_cv, t_bit}, source}, words) do
    {k, s} = cv_k_s(t_step, t_cv)
    cvs = all_cv(words)

    targ_bit = cv_bit(cvs, {t_step, t_cv, t_bit})
    source_bit = cv_bit(cvs, source)

    if source_bit != targ_bit do
      fixed = set_cv_bit(cvs, {t_step, t_cv, t_bit}, source_bit)

      [a, d, c, b] = Enum.slice(cvs, k..(k + 3))
      new_m  = (rrot(fixed, s) - a - MD4.f(b, c, d)) &&& @mask
      List.replace_at(words, k, new_m)
    else
      words
    end
  end

  def second_round_step_fix_a_reduce(t_s, words), do: second_round_step_fix_a(words, t_s)
  def second_round_step_fix_a(words, {target, source}) do
    cvs = all_cv(words, 8)
    source_bit = cv_bit(cvs, source)
    if cv_bit(cvs, target) != source_bit do
      if debug_fixes? do
        IO.inspect ['Fixing round 2 a', target, source, cv_bit(cvs, target), source_bit]
      end
      precise_change_a(cvs, words, target)
    else
      words
    end
  end

  def second_round_step_fix_b(words, {target, source} ) do
    cvs = all_cv(words, 8)
    source_bit = cv_bit(cvs, source)
    if cv_bit(cvs, target) != source_bit do
      if debug_fixes? do
        IO.inspect ['Fixing round 2 b', target, source, cv_bit(cvs, target), cv_bit(cvs, source)]
      end
      precise_change_b(cvs, words, target)
    else
      words
    end
  end

  def precise_change_a(cvs, words, target) do
    {t_step, t_cv, t_bit} = target
    {k, s} = cv_k_s(t_step, t_cv)

    # These don't necessarily line up with real chain var names.
    [a0, d0, c0, b0, a1, d1, c1, b1, a2] = Enum.slice(cvs, k..(k + 8))

    [{_, s0}, {_, s1}, {_, s2}, {_, s3}, {_, s4}] = List.flatten(MD4.round_1)
                                                    |> Enum.slice(k..(k + 4))

    mw = Enum.at(words, k)
    m_bit = t_bit - s
    sign = (to_bits(a1) |> Enum.at((t_bit - s + s0) &&& 31)) * -2 + 1
    new_mw = (mw + (sign * round(:math.pow(2, m_bit)))) &&& @mask
    new_a1 = (a0 + MD4.f(b0, c0, d0) + new_mw) |> MD4.lrot(s0)

    List.replace_at(words, k, new_mw)
    |> List.replace_at(k + 1, (rrot(d1, s1) - d0 - MD4.f(new_a1, b0, c0)) &&& @mask)
    |> List.replace_at(k + 2, (rrot(c1, s2) - c0 - MD4.f(d1, new_a1, b0)) &&& @mask)
    |> List.replace_at(k + 3, (rrot(b1, s3) - b0 - MD4.f(c1, d1, new_a1)) &&& @mask)
    |> List.replace_at(k + 4, (rrot(a2, s4) - new_a1 - MD4.f(b1, c1, d1)) &&& @mask)
  end

  def precise_change_b(cvs, words, target) do
    {t_step, t_cv, t_bit} = target
    {k, s} = cv_k_s(t_step, t_cv)

     # 5    6    7   8   9
    [m0, _m1, _m2, m3, m4] = Enum.slice(words, (k - 3)..(k + 1))
    [{_, s0}, {_, s1}, {_, s2}, {_, s3}, {_, s4}] = List.flatten(MD4.round_1)
                                                    |> Enum.slice((k - 3)..(k + 1))

    new_m0 = (m0 + (:math.pow(2, t_bit - s - s0) |> round)) &&& @mask

    # The d5,18 change in A can corrupt our first round condition for c5,26
    # Just go through the whole thing in that case.
    if cv_bit(cvs, {2, :a, t_bit - 9}) == cv_bit(cvs, {1, :b, t_bit - 9}) do
      new_m3 = (m3 - (:math.pow(2, t_bit - s) |> round)) &&& @mask
      new_m4 = (m4 - (:math.pow(2, t_bit - s) |> round)) &&& @mask

      List.replace_at(words, k - 3, new_m0)
      |> List.replace_at(k, new_m3)
      |> List.replace_at(k + 1, new_m4)
    else
      [d1, c1, b1, a2, _d2, c2, b2, a3, d3] = Enum.slice(cvs, (k - 3)..(k + 5))
      new_d2 = (d1 + MD4.f(a2, b1, c1) + new_m0) |> MD4.lrot(s0)

      List.replace_at(words, k - 3, new_m0)
      |> List.replace_at(k - 2, (rrot(c2, s1) - c1     - MD4.f(new_d2, a2,     b1))     &&& @mask)
      |> List.replace_at(k - 1, (rrot(b2, s2) - b1     - MD4.f(c2,     new_d2, a2))     &&& @mask)
      |> List.replace_at(k,     (rrot(a3, s3) - a2     - MD4.f(b2,     c2,     new_d2)) &&& @mask)
      |> List.replace_at(k + 1, (rrot(d3, s4) - new_d2 - MD4.f(a3,     b2,     c2))     &&& @mask)
    end
  end

  def all_cv(words, step_limit \\ 4) do
    {aa, bb, cc, dd} = MD4.init
    [aa, dd, cc, bb] ++
    (
      Enum.slice(MD4.all_steps, 0..(step_limit - 1))
      |> Enum.map_reduce({MD4.init, words}, fn(r_params, accum) ->
        {{a, b, c, d}, words} = MD4.compress_step(r_params, accum)
        {[a, d, c, b], {{a, b, c, d}, words}}
      end)
      |> elem(0)
    )
    |> List.flatten
  end

  def set_cv_bit(all_cv, {t_step, t_cv, t_bit}, source) do
    cv_bits(all_cv, t_step, t_cv) |> List.replace_at(t_bit, cv_bit(all_cv, source)) |> from_bits
  end

  def cv(all_cv, step, name), do: Enum.at(all_cv, cv_idx(step, name))
  def cv_bits(all_cv, step, name), do: cv(all_cv, step, name) |> to_bits

  def cv_bit(cvs, step, name, bit) when bit < 0, do: cv_bit(cvs, step, name, -bit) * -2 + 1
  def cv_bit(cvs, step, name, bit), do: cv_bits(cvs, step, name) |>  Enum.at(bit)
  def cv_bit(cvs, {step, name, bit}), do: cv_bit(cvs, step, name, bit)
  def cv_bit(_cvs, n), do: n

  def cv_idx(step, cv), do: 4 * step + cv_offset(cv)
  def cv_offset(cv), do: Enum.find_index([:a, :d, :c, :b], &(&1 == cv))
  def cv_k_s(cv_step, cv) do
    MD4.all_steps |> Enum.at(cv_step - 1) |> elem(0) |> Enum.at(cv_offset(cv))
  end

  def to_bits(n) do
    b = Integer.digits(n, 2)
    (MD4.zeros(32 - length(b)) ++ b) |> Enum.reverse
  end
  def from_bits(l), do: Enum.reverse(l) |> Integer.undigits(2)

  def rrot(n, s), do: ((n <<< (32 - s)) &&& @mask) ||| ((n &&& @mask) >>> s)
  def rand_bytes(n), do: (for _ <- 1..n, do: :crypto.rand_uniform(1, 0xff))
  def rand_m, do: rand_bytes(64)

  def check_round(words, fixes, debug \\ true)
  def check_round(m, fixes, debug) when length(m) != 16 do
    MD4.split_words(m) |> check_round(fixes, debug)
  end
  def check_round(words, fixes, debug) do
    cvs = all_cv(words, 12)
    Enum.reduce(fixes, 0, fn({targ, source}, c) ->
      t_bit = cv_bit(cvs, targ)
      s_bit = cv_bit(cvs, source)
      if t_bit == s_bit do
        c
      else
        if debug do
          IO.puts "\tMissing condition: #{inspect {targ, source}} #{inspect {t_bit, s_bit}}"
        end
        c + 1
      end
    end)
  end

  def count_errors(m), do: check_round(m, @fixes_1 ++ @fixes_2 ++ @fixes_3, false)

  def check_round_1(m, debug \\ true), do: check_round(m, @fixes_1, debug)
  def check_round_2(m, debug \\ true), do: check_round(m, @fixes_2, debug)
  def check_round_3(m, debug \\ true), do: check_round(m, @fixes_3, debug)

  def check_rounds(hex) when is_binary(hex), do: from_hex(hex) |> check_rounds
  def check_rounds(m) do
    IO.puts "-- Errors in round 1: #{check_round_1(m)}"
    IO.puts "-- Errors in round 2: #{check_round_2(m)}"
    IO.puts "-- Errors in round 3: #{check_round_3(m)}"
    m
  end

  @bit_fmt String.duplicate("~3B", 32) <> "~n"
  @tf_fmt String.duplicate("~3s", 32) <> "~n"
  def compare_bits(x, y) do
    IO.puts "Comparing bits of #{x} with #{y}"
    debug_bit_header
    debug_bits(x)
    debug_bits(y)
    debug_bits_diff(x, y)
  end
  def compare_bits(l) when is_list(l) do
    prefix = "      "
    debug_bit_header(prefix)
    Enum.each(l, fn({n, x}) -> debug_bits(x, n) end)
    if length(l) == 2 do
      [{_, x}, {_, y}] = l
      debug_bits_diff(x, y, prefix)
    end
  end
  def debug_bit_header(prefix \\ ""), do: :io.format prefix <> @bit_fmt, Enum.to_list(0..31)
  def debug_bits(x), do: :io.format(@bit_fmt, to_bits(x))
  def debug_bits(x, name), do: :io.format("~4s: " <> @bit_fmt, [name | to_bits(x)])
  def debug_bits_diff(x, y, prefix \\ "") do
    :io.format prefix <> @tf_fmt, Enum.zip(to_bits(x), to_bits(y)) |> Enum.map(fn({a, b}) ->
      if a == b, do: ' ', else: 'f'
    end)
  end

  def debug_fixes?, do: Process.get(:debug_fixes)

  def from_hex(b), do: Base.decode16!(b, case: :lower) |> :binary.bin_to_list
  def to_hex(l), do: IO.iodata_to_binary(l) |> Base.encode16(case: :lower)

  def check_for_round_one_breaks do
    for idx <- 1..1000 do
      orig = Attack.rand_m
      m = Attack.modify_m(orig)
      if Attack.check_round_1(m, false) > 0 do
        IO.puts "Broke first round at #{idx}!"
        IO.puts "Trying\n\t#{Attack.to_hex(orig)}"
        IO.puts "\t#{Attack.to_hex(m)}"
        Process.put(:debug_fixes, true)
        Attack.modify_m(orig)
        Attack.check_rounds(m)
        exit(1)
      end
    end
  end
end

tests = [["cats", "f99c58ff7935b1f658d74aaa36497bdb"],
         ["", "31d6cfe0d16ae931b73c59d7e0c089c0"],
         ["a", "bde52cb31de33e46245e05fbdbd6fb24"],
         ["abc", "a448017aaf21d8525fc10ae87aa6729d"],
         ["message digest", "d9130a8164549fe818874806e1c7014b"],
         ["abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"],
         ["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
          "043f8582f241db351ce627e153e7f0e4"],
         ["12345678901234567890123456789012345678901234567890123456789012345678901234567890",
          "e33b4ddc9c38f2199c3e7b164fcc0536"]]

for [a, b] <- tests do
  hex = (MD4.hash(a) |> Attack.to_hex)
  unless hex == b do
    IO.puts "MD4 tests failed!"
    IO.puts "For: #{a} Expected: #{b} Got: #{hex}"
    exit(1)
  end
end
IO.puts "MD4 tests passed"

examples = [
  # Wikipedia
  {
    "839c7a4d7a92cb5678a5d5b9eea5a7573c8a74deb366c3dc20a083b69f5d2a3bb3719dc69891e9f95e809fd7e8b23ba6318edd45e51fe39708bf9427e9c3e8b9",
    "839c7a4d7a92cbd678a5d529eea5a7573c8a74deb366c3dc20a083b69f5d2a3bb3719dc69891e9f95e809fd7e8b23ba6318edc45e51fe39708bf9427e9c3e8b9"
  },
  # Found
  {
    "774f9f9f1316c056da115ea4de90f2e557850ef2190ef9c8691c404b003e14a0c13a39d95fa64e8e13fbfcee03b7e02f9e0715ca87b1c1b2f799847f7e7434bd",
    "774f9f9f1316c0d6da115e14de90f2e557850ef2190ef9c8691c404b003e14a0c13a39d95fa64e8e13fbfcee03b7e02f9e0714ca87b1c1b2f799847f7e7434bd",
  }
]

for {a, b} <- examples do
  m = Attack.from_hex(a)
  m2 = Attack.from_hex(b)
  derived = Attack.derive_m2(m)
  unless derived == m2, do: IO.puts "M2 Derive for example failed! #{a}"
end

# Attack.check_for_round_one_breaks

# Currently somewhere around 2**10..2**14 tries to get collision. Seems good enough.
IO.inspect(Attack.find_collision |> Enum.map(&Attack.to_hex/1))

if Process.get(:md4) > 0 && Process.get(:ms) > 0 do
  IO.puts "
    Stats
    -----
      MD4 Hashes:    #{Process.get(:md4)}  |  #{Process.get(:md4) |> :math.log2}
      Messages made: #{Process.get(:ms)}  |  #{Process.get(:ms) |> :math.log2}

  "
end
