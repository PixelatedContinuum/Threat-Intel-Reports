#!/usr/bin/env ruby
# Renders one report twice with the site's own Jekyll layouts, so the completeness
# and browser gates have a baseline for a report that is not published yet.
#
#   ruby render-report.rb <report folder holding index.md | path to index.md> <out dir> [baseline index.md]
#
# Writes into <out dir>:
#   tagged.html     the report as written (tab lines kept)
#   untagged.html   the same markdown with every "{: .hl-tab-<token>}" line removed:
#                   the completeness baseline (check-report-text.js --baseline). With a third
#                   argument the baseline is rendered from THAT markdown instead (tab lines
#                   stripped), so words lost between an earlier copy (the vault's) and this
#                   one show as missing; the page is still this report's own
#   custom.css      assets/css/custom.scss compiled the way Jekyll does
#   render.json     { slug, folder, permalink, tab_lines, jekyll, kramdown }
#
# The report may live OUTSIDE this checkout (threat-intel-vault/reports/<slug>/).
# Nothing is written to this checkout: the site's _includes, _data and the two
# layouts are linked into a scratch source tree under <out dir>/src.
#
# GEMS NEEDED: jekyll (3.x), jekyll-seo-tag, kramdown-parser-gfm, sass (the Ruby
# Sass 3.7 gem; `gem install sass`), json. When one is missing this exits 2 with
# "NOT CHECKED" and the gem named: a gate that could not render has not passed.
#
# Exit 0 rendered, 1 the render failed, 2 NOT CHECKED (a gem is missing) or usage.

def not_checked(reason)
  puts "NOT CHECKED  render-report.rb: #{reason}"
  exit 2
end

begin
  require 'fileutils'
  require 'json'
  require 'yaml'
  require 'jekyll'
  require 'jekyll-seo-tag'
  require 'sass'
rescue LoadError => e
  not_checked("#{e.message}. Install the missing gem (gem install jekyll jekyll-seo-tag sass kramdown-parser-gfm), then re-run.")
end

if ARGV.length < 2 || ARGV.length > 3
  warn 'usage: ruby render-report.rb <report folder | path to index.md> <out dir> [baseline index.md]'
  exit 2
end

repo = ENV['REPO'] || File.expand_path('../..', __dir__)
arg = File.expand_path(ARGV[0])
out = File.expand_path(ARGV[1])
file = File.directory?(arg) ? File.join(arg, 'index.md') : arg
unless File.file?(file)
  warn "no report markdown at #{file}"
  exit 2
end
baseline_file = ARGV[2] ? File.expand_path(ARGV[2]) : nil
baseline_file = File.join(baseline_file, 'index.md') if baseline_file && File.directory?(baseline_file)
if baseline_file && !File.file?(baseline_file)
  warn "no baseline markdown at #{baseline_file}"
  exit 2
end
folder = File.basename(File.dirname(file))
raw = File.read(file)
baseline_raw = baseline_file ? File.read(baseline_file) : raw
fm = raw[/\A---\r?\n(.*?)\r?\n---/m, 1]
permalink = fm && (YAML.safe_load(fm, permitted_classes: [Date, Time]) || {})['permalink']
slug = permalink ? permalink.to_s.sub(%r{\A/reports/}, '').sub(%r{/\z}, '') : folder

TAB_LINE = /^\{: \.hl-tab-[a-z]+\}\r?\n/
tab_lines = raw.scan(TAB_LINE).length

src = File.join(out, 'src')
FileUtils.rm_rf(src)
FileUtils.mkdir_p(File.join(src, '_layouts'))
%w[_includes _data].each { |d| FileUtils.ln_s(File.join(repo, d), File.join(src, d)) }
%w[default.html post.html].each { |l| FileUtils.cp(File.join(repo, '_layouts', l), File.join(src, '_layouts', l)) }

config = Jekyll.configuration(
  'source' => src, 'destination' => File.join(out, 'gen'), 'config' => File.join(repo, '_config.yml'),
  'plugins' => ['jekyll-seo-tag'], 'remote_theme' => nil, 'quiet' => true,
  'github' => { 'build_revision' => 'render-report' },
  'markdown' => 'kramdown', 'kramdown' => { 'input' => 'GFM' }, 'exclude' => []
)

def render(config, src, folder, markdown)
  dir = File.join(src, 'reports', folder)
  FileUtils.rm_rf(File.join(src, 'reports'))
  FileUtils.mkdir_p(dir)
  File.write(File.join(dir, 'index.md'), markdown)
  site = Jekyll::Site.new(config)
  site.reset
  site.read
  page = site.pages.find { |p| p.path == "reports/#{folder}/index.md" }
  raise "Jekyll did not read reports/#{folder}/index.md" unless page
  Jekyll::Renderer.new(site, page).run
end

begin
  FileUtils.mkdir_p(out)
  File.write(File.join(out, 'tagged.html'), render(config, src, folder, raw))
  File.write(File.join(out, 'untagged.html'), render(config, src, folder, baseline_raw.gsub(TAB_LINE, '')))
  css = File.read(File.join(repo, 'assets/css/custom.scss')).sub(/\A---\n---\n/, '')
            .gsub(/\{%-?\s*comment\s*-?%\}.*?\{%-?\s*endcomment\s*-?%\}/m, '')
  File.write(File.join(out, 'custom.css'), Sass::Engine.new(css, syntax: :scss, style: :compressed).render)
  File.write(File.join(out, 'render.json'), JSON.pretty_generate(
    'slug' => slug, 'folder' => folder, 'permalink' => permalink, 'tab_lines' => tab_lines, 'baseline' => baseline_file,
    'jekyll' => Jekyll::VERSION, 'kramdown' => Kramdown::VERSION
  ))
rescue StandardError => e
  puts "FAIL  render-report.rb: #{e.class}: #{e.message.lines.first}"
  exit 1
end
puts "rendered #{slug}: tagged.html, untagged.html (#{tab_lines} tab line(s) stripped), custom.css in #{out}"
