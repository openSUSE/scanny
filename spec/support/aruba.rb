require 'aruba/api'

module Aruba
  module Api
    def remove_dir(directory_name)
      in_current_dir do
        FileUtils.rmdir(directory_name)
      end
    end
  end
end

extra_path_folder = File.join(File.expand_path(File.dirname(__FILE__)), '../bin')
ENV['PATH'] = [extra_path_folder, ENV['PATH']].join(File::PATH_SEPARATOR)