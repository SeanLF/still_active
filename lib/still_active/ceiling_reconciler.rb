# frozen_string_literal: true

module StillActive
  # Whole-tree correlation between the two capping signals, run once after the
  # fan-out (native or SBOM) has assembled every package's findings. A language
  # ceiling that says "upgrade <package> to lift it" is wrong if the same tree
  # poisons <package> below that upgrade (a dormant dependency caps it): the
  # report must never advise an upgrade its own poison finding says is impossible.
  # All data is already in the assembled result, so this is one pass, no fetches.
  # "The correlation layer must correlate."
  module CeilingReconciler
    extend self

    def reconcile_ceiling_with_poison(result_object)
      # Qualify each capped dependency by the ecosystem that declares the cap. A
      # capped dep resolves in its parent's ecosystem, so a poison finding on a
      # `pypi` package caps a `pypi` dependency. A mixed SBOM has two flat-
      # resolution ecosystems (rubygems + pypi), so a bare-name match alone would
      # let a rubygems poison-cap on "foo" wrongly block a pypi "foo"'s ceiling.
      # Native results carry no :ecosystem (all rubygems) -> nil on both sides,
      # still consistent.
      capped = result_object.each_value
        .flat_map do |data|
          Array(data[:constraints])
            .select { |constraint| constraint[:majors_behind].to_i.positive? }
            .map { |constraint| "#{data[:ecosystem]}/#{constraint[:dependency]}" }
        end
        .uniq
      result_object.each do |key, data|
        ceiling = data[:language_ceiling]
        next unless ceiling && ceiling[:fixed_by_upgrade]

        # Native results are keyed by the bare gem name; SBOM results are keyed by
        # "ecosystem/name@version" and carry the bare name in :name.
        package_name = data[:name] || key
        next unless capped.include?("#{data[:ecosystem]}/#{package_name}")

        ceiling[:fixed_by_upgrade] = false
        ceiling[:upgrade_blocked] = true
      end
    end
  end
end
