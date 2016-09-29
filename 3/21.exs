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


MT19937.seed(400)

expected = {2872168796, 3400076751, 970656062, 807842745, 3690659980, 3163100147, 1247232407,
3602345222, 636582133, 3613814920, 51747435, 1015100607, 3333556422, 4001783323, 1738328422,
2654202143, 3676321954, 1197502977, 2314066087, 3938499342, 2189100113, 1058237765, 1613859506,
742937111, 739114773, 1652905678, 656166660, 2791013219, 3969143985, 2094331250, 152146830,
3316943084, 3636400948, 3747028785, 2739882179, 818245065, 2144797601, 2870004692, 4164026074,
2761483670, 2816391453, 3820792061, 2960133995, 3006966252, 3108983724, 2118357964, 1849507713,
2153633829, 822346992, 993058938, 3409330291, 1341479284, 4152373607, 91525637, 439695909,
4177467300, 1398351683, 1156842442, 599852888, 88265518, 3556115264, 3756209697, 4049940308,
930602964, 1934353205, 4216452486, 2443108779, 3203449704, 2233869490, 869347535, 4283464420,
3394517850, 950702226, 1057063891, 3454378333, 2253592727, 3296405337, 2434590723, 2607539727,
1393813300, 1692115668, 2492756224, 4103346901, 1923630153, 3140993247, 1796093200, 1510240092,
2244668369, 2362108514, 1601297772, 2874943462, 2604584080, 4027306950, 4017237993, 2656882346,
4179929751, 107259415, 1003551056, 222749346, 265264199, 890745201, 2131231822, 859154790,
162649612, 3609700463, 1890197407, 3237707423, 834480298, 3055367112, 2629996752, 602123395,
787639124, 2380841374, 1969164887, 4074184282, 2690050381, 422271776, 2422731706, 2704533777,
194228442, 2598139778, 2946199717, 2398299539, 1570142428, 2358599810, 3271335136, 3562135350,
114588515, 1718886920, 2504941490, 98978705, 42954371, 1733692328, 3966393771, 2930099217,
2026737106, 4231608313, 1813872320, 3798402071, 1826301774, 388881895, 2199144575, 2852386545,
199424657, 1276577612, 1360432356, 4003518416, 2793649907, 3355962174, 3087687905, 701105781,
1610550598, 1477876654, 1987367846, 3281460638, 2228286353, 2592427204, 3583378187, 1104962011,
3919371076, 2417232477, 1330715757, 2359828571, 3478793859, 3805387746, 3305441690, 530109853,
167663120, 1634865611, 860618286, 2593561004, 2752284967, 402043305, 3489186614, 942596132,
2604169612, 2709629, 1802279707, 2006499179, 868726700, 2571052195, 3002651432, 422722880,
2199103075, 1076434620, 3796702060, 1024100014, 2425862279, 1336307518, 2067596228, 2228591351,
3069702662, 184209534, 2213660243, 1967634792, 3905381494, 3127858559, 1860454790, 4077818559,
81893897, 1512384865, 2881461341, 2908792315, 2281734721, 55673369, 3973104244, 3205758576,
1388248498, 1983272959, 3594387365, 2195645064, 410883263, 3237225566, 787353237, 1015494407,
1225310795, 3331792341, 589910144, 385523070, 3672182441, 210462150, 791220206, 2447873578,
947817402, 3220534911, 116699921, 645190753, 906655637, 2828498086, 2563503232, 2369736472,
574350264, 844280939, 3582501859, 2532688655, 1077770728, 1632263145, 1146734997, 3420225817,
1420292685, 2813844807, 2639530699, 1267396986, 2572892633, 673445778, 1131118975, 258881157,
193901862, 1975933229, 1145801319, 1601242235, 178189991, 834951898, 1036522016, 1545911445,
570071332, 677926662, 1833562466, 4069107112, 1439427766, 1878703636, 3555691284, 1525507272,
456976112, 2837413410, 3414329341, 3023799993, 3506797717, 670434160, 1047642586, 3406056505,
1224534327, 3887350817, 1640442613, 4103460474, 2579077629, 4184894704, 3912972206, 1717599155,
1282412493, 2990193189, 3719935692, 3334701412, 1447065108, 2080533390, 3170225596, 875832144,
3843795892, 2300518207, 853318446, 353529145, 493849195, 2706679444, 1845934894, 886381599,
1480294844, 3010841732, 3207337342, 176224566, 4009723710, 3036911024, 4209191850, 1579079027,
1660782897, 3870441091, 26417152, 339849180, 4172137022, 2627701878, 4264666165, 967155758,
690482337, 2800154169, 3250561795, 910030435, 1389471074, 1196612875, 3047820170, 2701187676,
4137211880, 2831168097, 926353034, 255870952, 1759538737, 1679053425, 4276512208, 3406527433,
2583937959, 3623905753, 1738262919, 871179287, 2213100828, 907030665, 1402218085, 1818916927,
722769862, 561632780, 3968894567, 727410674, 2163831324, 2645223913, 3318996814, 2771596086,
900136762, 820625438, 3081190771, 1522089825, 1213657091, 320242698, 2845166470, 1360515312,
2374723324, 1235344171, 1316896797, 2500933995, 1166674263, 3036570024, 1402705545, 4142459580,
2029530097, 3670364257, 2196950939, 2127743732, 3740446119, 1703737067, 4112895538, 864502231,
800083481, 2606990942, 2094269209, 3774080711, 1497058306, 2173885902, 338272149, 2180871509,
3810505518, 2231161840, 1089770168, 3444866364, 655010794, 1928131605, 381313264, 62792220,
1481891877, 1455716048, 1275334279, 2775989139, 1368603183, 3378609331, 2589353024, 4025277211,
1481058445, 1697674646, 1673647483, 466850251, 2297836485, 296932660, 3568344207, 55831695,
2369860454, 954654340, 3792762977, 2298892653, 2328220967, 2926015438, 514289268, 1110361375,
2471385725, 1355579752, 2543248136, 3224269911, 3345197334, 2203862081, 1563301537, 2652619307,
892937861, 2128177304, 4170460749, 3368180352, 3158045606, 1871129651, 3505910660, 3045463449,
1879330008, 3341379772, 2495046197, 1461652528, 186175678, 1826866586, 133455733, 1761958655,
3282148872, 1975918755, 1638724963, 1026829683, 872754150, 840072426, 1113208179, 2134402665,
3116198386, 3243228017, 3384238380, 906271945, 1955625389, 2252573958, 613103275, 267335463,
1745427864, 603819180, 4218628709, 3425122867, 941388529, 685277653, 3347583175, 1584604015,
448895340, 4175347144, 2546693035, 1229947172, 1281874878, 3329715801, 1222759513, 447778767,
122625437, 2421016507, 1330259391, 316170256, 1922835498, 1928403580, 2187774172, 2227250269,
296342362, 2707526230, 1182233565, 281972354, 2203458997, 471992684, 316936316, 3297880290,
2589021945, 984281251, 175756500, 3068806408, 1125702380, 1861225625, 2214709736, 2689531667,
4291388473, 2376471920, 1070969208, 3733256914, 2795644510, 3808020659, 1989178671, 2560004666,
3648390423, 3943428639, 1886332175, 417017468, 4213474712, 866318977, 4101272788, 3134040214,
511414226, 1926789196, 2298986900, 4043421897, 3805925683, 3825623595, 1084815900, 1139115194,
405811866, 1104809138, 2238813400, 4068741554, 3866108780, 1114459363, 2910151928, 3504842468,
707594383, 509907958, 3273082823, 2333354789, 3151279669, 2915808603, 541696291, 1288903751,
515755402, 1674943595, 3005937840, 3470439793, 2796100520, 1812497243, 110178916, 4270370513,
1487372862, 4066876404, 4202533266, 4121576624, 1459460330, 947849967, 787765290, 339383127,
2873576498, 2297234559, 2434443032, 958686429, 1521390053, 2104524945, 1557951956, 2027177212,
549214173, 1551175181, 2002938138, 2368990387, 3271043046, 4018188745, 1712708559, 2648382265,
2901185763, 1746879054, 3360909997, 2495399808, 2137022886, 1859158727, 3212234000, 1013561351,
557722053, 1917338268, 2254940038, 3951375518, 3092480564, 2559691448, 3866733866, 2150506367,
2234940041, 3208590439, 2217088635, 411353479, 4040229891, 2545094957, 1020180201, 980835259,
2154687601, 1219918878, 3050582200, 1033416286, 2731636343, 1795747976, 1900986207, 3171050327,
3085791813, 2533907286, 886519605, 3427845304, 1635668951, 341510302, 2090001446, 2010905937,
1366672587, 3122460798, 3152573250, 2106774835, 1884232078, 1360291753, 1649900890, 3843845624,
2332046024, 432546551, 1741369431, 2032180299, 1185661160, 4139889434, 1398538767, 1187287978,
2780887800, 3652012398, 2111529088, 3869970878, 1240436776, 1681917535, 605024004, 3606525837,
3978589145, 385829614, 2594819100, 2882275613, 994610335, 2514860797, 895631932, 1526436084,
2100849364, 2593659283, 1392453116, 2415808535, 3988799319, 4071518546, 1995977186, 2972942914,
1511110894, 2000530624, 3011368021, 1627659989, 3264876902, 2946861697, 3574623330, 3045812545,
1727320548, 989747185, 3916443909, 1157832938, 2605460847, 2418668216, 3595583823, 3982434534,
3539978521, 1349726895, 2342585111, 2884061413, 1453503312, 3457739270, 838217441, 3780072684,
1865227088, 3035120726, 3612680201, 1153457340, 1746367000, 3962682211, 2405114137, 952146464,
1886940633, 4099692613, 437187529, 3737228590, 935943019, 2071118464, 2551159149, 2911733656,
3519460945, 2483078615, 3544070817, 2903119208, 85393773, 1761693180, 2279889480, 1366562238,
2348931831, 3661054405, 1181310550, 1974441734, 2855442201, 2992864609, 4159955595, 2127917599,
2050128656, 3733994792, 2374841173, 3620588491}

for n <- 0..(tuple_size(expected) - 1) do
  actual = MT19937.rand
  exp = elem(expected, n)
  if exp != actual do
    IO.inspect [n, exp, actual, exp == actual]
    raise "Bad!"
  end
end
IO.puts "All good!"
