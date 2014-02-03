"""Sphinx plugin for automatically generating (and optionally cleaning) project api documentation

To enable the optional cleaning, set ``clean_autogenerated_docs`` to ``True`` in docs/conf.py

"""
import subprocess

from sphinx.util.console import bold, red

from utils.path import docs_path, project_path

# When adding/removing from this list, remember to edit docs/modules.rst to match
#: List of modules/packages to document, paths relative to the project root.
modules_to_document = ['cfme', 'fixtures', 'utils']
_doc_modules_path = docs_path.join('modules')


def setup(sphinx):
    """Main sphinx entry point, calls sphinx-apidoc"""
    for module in modules_to_document:
        module_path = project_path.join(module).strpath
        output_module_path = _doc_modules_path.join(module).strpath
        # Shove stdout into a pipe to supress the output, but still let stderr out
        args = ['sphinx-apidoc', '-T', '-e', '-o', output_module_path, module_path]
        proc = subprocess.Popen(args, stdout=subprocess.PIPE)
        proc.wait()
    sphinx.add_config_value('clean_autogenerated_docs', False, rebuild='')
    sphinx.connect('build-finished', purge_module_apidoc)


def purge_module_apidoc(sphinx, exception):
    # Short out if not supposed to run
    if not sphinx.config.clean_autogenerated_docs:
        return

    try:
        sphinx.info(bold('cleaning autogenerated docs... '), nonl=True)
        _doc_modules_path.ensure(dir=True)
        _doc_modules_path.remove(rec=True)
        sphinx.info(message='done')
    except Exception as ex:
        sphinx.info(red('failed to clean autogenerated docs'))
        sphinx.info(red(type(ex).__name__) + ' ', nonl=True)
        sphinx.info(ex.message)
