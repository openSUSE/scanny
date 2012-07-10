module Scanny
  module CLI
    def build_paths
      paths = ARGV.map do |path|
        path += "/**/*.rb" if File.directory?(path)
        path
      end
      paths << "./**/*.rb" if paths.size == 0

      paths
    end
  end
end