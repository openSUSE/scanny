require 'aruba/api'

extra_path_folder = File.join(File.expand_path(File.dirname(__FILE__)), '../bin')
ENV['PATH'] = [extra_path_folder, ENV['PATH']].join(File::PATH_SEPARATOR)