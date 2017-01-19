defmodule S4Ch31.Mixfile do
  use Mix.Project

  def application do
    [applications: [:cowboy, :plug]]
  end

  def project do
    [app: :s4_ch31,
     version: "1.0.0",
     deps: deps]
  end

  defp deps do
    [
      {:cowboy, "~> 1.0.0"},
      {:plug, "~> 1.0"}
    ]
  end
end
