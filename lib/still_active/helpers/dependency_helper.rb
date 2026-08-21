# frozen_string_literal: true

module StillActive
  # The canonical identity of an assessed dependency, shared by every renderer
  # (terminal/markdown/SARIF display) and by the suppression matchers (--ignore
  # and .still_active.yml).
  module DependencyHelper
    extend self

    # A cross-ecosystem SBOM dependency is "ecosystem/name" (the lens sets
    # :ecosystem and :name); a native gem is its bare name (the hash key), where
    # gem_data carries no :ecosystem. Deliberately version-independent: it is NOT
    # the composite "ecosystem/name@version" hash key, so one suppression covers a
    # dependency across version bumps and matches the same identity the poison /
    # ceiling correlators key on.
    def identity(name, data)
      data[:ecosystem] ? "#{data[:ecosystem]}/#{data[:name]}" : name
    end
  end
end
