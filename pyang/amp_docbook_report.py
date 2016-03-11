''' A pyang plugin which exports a ADM-defining YANG "module" tree to a 
DocBook "reference" tree containing detailed breakdown of the module contents.
'''

import sys
import copy
import logging
import pyang.plugin
#import pyang.syntax
#import pyang.grammar
import pyang.statements
#import pyang.plugins.tree
import mako.template
#import xml.etree.ElementTree as ET
from amp_adm import MODULE_NAME

logger = logging.getLogger(__name__)

#: Top-level template for multiple modules.
# 
DOC_TEMPLATE = '''\
<?xml version="1.0" encoding="utf8"?>
<reference xmlns="http://docbook.org/ns/docbook">
    <info>
        <title>Management Information Base Content</title>
    </info>
    %for mod_desc in mod_descriptors:
    ${module_tmpl.render(module=mod_desc, toc_item_tmpl=toc_item_tmpl, detail_item_tmpl=detail_item_tmpl)}
    %endfor
</reference>
'''

#: Template for each individual module
MODULE_TEMPLATE = '''\
<refentry xml:id="refentry.${module.name |u}">
    <info>
        <orgname>${module.organization |h}</orgname>
    </info>
    <refmeta>
        <refentrytitle>${module.name |h}</refentrytitle>
        <manvolnum>3</manvolnum>
    </refmeta>
    <refsynopsisdiv>
        <title>Module Description</title>
        <para>
            ${module.description |h}
        </para>
        <para>
            Module from: ${module.organization |h}
        </para>
    </refsynopsisdiv>
    <refsect1>
        <title>Summary Tree</title>
        <para>
          MIB tree:
          <variablelist>
            %for sub_item in module.items:
            ${toc_item_tmpl.render(item=sub_item, toc_item_tmpl=toc_item_tmpl)}
            %endfor
          </variablelist>
        </para>
    </refsect1>
    <refsect1>
        <title>Detailed Descriptions</title>
        %for sub_item in module.items:
        ${detail_item_tmpl.render(item=sub_item, detail_item_tmplb=detail_item_tmpl)}
        %endfor
    </refsect1>
</refentry>
'''

# Recursive template with nested content
TOC_ITEM_TEMPLATE = '''\
<varlistentry>
  <term><link linkend="detail.${item.uid}"><systemitem>${item.name |h}</systemitem></link> (${item.keyword})</term>
  <listitem>
    <simpara>
    ${item.summary |h}
    </simpara>
    %if item.keyword in ('container', ('amp-adm', 'group'), 'list', 'notification'):
    <para>
      %if item.keyword in ('container', ('amp-adm', 'group')):
      Group of items:
      %elif item.keyword == 'list':
      List of items:
      %elif item.keyword == 'notification':
      Notification containing items:
      %endif
      <variablelist>
          %for sub_item in item.items:
          ${toc_item_tmpl.render(item=sub_item, toc_item_tmpl=toc_item_tmpl)}
          %endfor
      </variablelist>
    </para>
    %endif
  </listitem>
</varlistentry>
'''

# Recursive template with tail-appended content
DETAIL_ITEM_TEMPLATE = '''\
<refsect2 xml:id="detail.${item.uid}">
    <title><systemitem>${item.path |h}</systemitem> (${item.keyword|h})</title>
    <para>${item.description |h}</para>
    %if item.oid:
        <simpara>OID: ${item.oid} </simpara>
    %endif

    <variablelist>
        <title>Parameters</title>
    %if item.keyword == 'typedef':
        <varlistentry>
            <term>Source type name:</term>
            <listitem>
                %if item.type_uid:
                <link linkend="detail.${item.type_uid}">
                %endif
                <systemitem>${item.type_name |h}</systemitem>
                %if item.type_uid:
                </link>
                %endif
            </listitem>
        </varlistentry>
        %if item.unit_name is not None:
        <varlistentry>
            <term>Own unit name:</term>
            <listitem>${item.unit_name |h}</listitem>
        </varlistentry>
        %endif
    %elif item.keyword == 'list':
        <varlistentry>
            <term>Key:</term>
            <listitem><systemitem>${item.key_name |h}</systemitem></listitem>
        </varlistentry>
        <varlistentry>
            <term>Unique sets:</term>
            <listitem><systemitem>${item.unique_names |h}</systemitem></listitem>
        </varlistentry>
    %elif item.keyword == 'leaf':
        <varlistentry>
            <term>Type name:</term>
            <listitem>
                %if item.type_uid:
                <link linkend="detail.${item.type_uid}">
                %endif
                <systemitem>${item.type_name |h}</systemitem>
                %if item.type_uid:
                </link>
                %endif
            </listitem>
        </varlistentry>
        <varlistentry>
            <term>Unit name:</term>
            <listitem><simpara>
            ${item.unit_name |h}
            %if item.unit_src is not None:
            (from <link linkend="detail.${item.unit_src[1] |u}">${item.unit_src[0] |h}</link>)
            %endif
            </simpara></listitem>
        </varlistentry>
        <varlistentry>
            <term>Edit type:</term>
            <listitem><simpara>
            ${('state', 'configuration')[item.is_config]}
            </simpara></listitem>
        </varlistentry>
    %endif
    </variablelist>
</refsect2>
%if item.keyword in ('container', 'list', 'notification'):
%for sub_item in item.items:
${detail_item_tmplb.render(item=sub_item, detail_item_tmplb=detail_item_tmplb)}
%endfor
%endif
'''

AMP_TYPES = [
    'amp:BYTE',
    'amp:INT',
    'amp:UINT',
    'amp:VAST',
    'amp:UVAST',
    'amp:REAL32',
    'amp:REAL64',
    'amp:SDNV',
    'amp:TS',
    'amp:BLOB',
]

class Context(object):
    ''' Keep track of non-statement-specific data related to the
    substatement tree within a module.
    '''
    
    def __init__(self, module):
        self._prefix_map = {}
        for imp in module.search('import'):
            name = imp.arg
            prefix = imp.search_one('prefix').arg
            self._prefix_map[prefix] = name
        
        # Lexically scoped types available
        self._typedef_stack = []
        # The base scope are built-in types
        builtins = {}
        for name in AMP_TYPES:
            builtins[name] = pyang.statements.Statement(None, None, None, 'type', name)
        self._typedef_stack.append(builtins)
    
    def _scope_enter(self, stmt):
        types_top = copy.copy(self._typedef_stack[-1])
        self._typedef_stack.append(types_top)
        logger.debug('Scope enter {0}\n'.format(stmt.arg))
        
        for typedef in stmt.search('typedef'):
            qualname = typedef.arg
            types_top[qualname] = typedef
    
    def _scope_exit(self, stmt):
        self._typedef_stack.pop()
        logger.debug('Scope exit {0}\n'.format(stmt.arg))
    
    def _find_typedef(self, name):
        types_top = self._typedef_stack[-1]
        try:
            return types_top[name]
        except KeyError:
            raise ValueError('Unknown type "{0}"'.format(name))
    
    def walk_tree(self, origin, reducer):
        ''' Walk a statement tree applying a specific reducer.
        
        :param origin: The original statement to search from.
        :param reducer: A function-like object which is called for 
            the origin statement and all of its parent statements.
            The reducer should raise StopIteration if it finishes
            before the root of the statement hierarchy.
        :return: The :py:obj:`reducer` after finishing the walk.
        '''
        next_stmt = origin
        while next_stmt:
            try:
                reducer(next_stmt)
            except StopIteration:
                break
            next_stmt = next_stmt.parent
        
        return reducer
    
    def walk_types(self, origin, sub_name, reducer):
        ''' Walk a typedef tree searching for a specific substatement name.
        
        :param origin: The original statement to search from.
        :param sub_name: The sub-statement name to search for.
        :param reducer: A function-like object which is called for the main
            statement and each subsequent typedef statements in the type chain.
            The reducer is called with a single argument of the sub-statement
            object at each level (which may be None for some levels).
            The reducer should raise StopIteration if it finishes
            before the root of the subtype hierarchy.
        :return: The :py:obj:`reducer` after finishing the walk.
        '''
        sub_stmt = origin.search_one(sub_name)
        next_type = origin.search_one('type')
        
        while next_type is not None:
            try:
                reducer(sub_stmt)
            except StopIteration:
                break
            typedef = self._find_typedef(next_type.arg)
            sub_stmt = typedef.search_one(sub_name)
            next_type = typedef.search_one('type')
        
        return reducer
    
class Descriptor(object):
    ''' Abstract storage for all tree nodes.
    
    :param ctx: The evaluation context for identifying scoped types.
    :type ctx: :py:class:`Context`
    :param stmt: The statement being evaluated into this descriptor.
    :type stmt: :py:class:`pyang.statements.Statement`
    '''
    
    HANDLER_CLASSES = {}
    
    def __init__(self, ctx, stmt):
        if stmt.keyword == 'module':
            self.path = None
        else:
            self.path = pyang.statements.mk_path_str(stmt)
        self.uid = self._path_uid(path=self.path)
        self.keyword = stmt.keyword
        self.name = stmt.arg
        desc = stmt.search_one('description')
        self.summary = self._trim_description(desc)
        self.description = arg_or_val(desc)
        logger.info('sub {0}'.format(', '.join([str(sub.keyword) for sub in stmt.substmts])))
        self.oid = arg_or_val(stmt.search_one((MODULE_NAME, 'fulloid')))
        
        self.items = []
        ctx._scope_enter(stmt)
        
        # Extract non-expanded statements first
        for sub in stmt.substmts:
            #logger.info(sub.keyword)
            if sub.keyword in ('container','list', 'leaf'):
                continue
            try:
                handler = Descriptor.HANDLER_CLASSES[sub.keyword]
            except KeyError:
                handler = None
            sys.stderr.write('key {0} handl \n'.format(sub.keyword, handler))
            
            if handler:
                self.items.append(handler(ctx=ctx, stmt=sub))
        
        # Expanded statements (i.e. leaves and parents)
        if hasattr(stmt, 'i_children'):
            for sub in stmt.i_children:
                try:
                    handler = Descriptor.HANDLER_CLASSES[sub.keyword]
                except KeyError:
                    handler = None
                #sys.stderr.write('key {0} handl \n'.format(sub.keyword, handler))
                
                if handler:
                    self.items.append(handler(ctx=ctx, stmt=sub))
        ctx._scope_exit(stmt)
    
    def _path_uid(self, stmt=None, path=None):
        if path is None:
            if stmt is None or stmt.parent is None:
                return None
            path = pyang.statements.mk_path_str(stmt)
        return path.replace('/', '.')[1:]
    
    def _trim_description(self, stmt):
        ''' Extract a substring only up to the first period charactor.
        
        :param stmt: The text statement to extract from.
        :type stmt: :py:class:`pyang.statements.Statement`
        :return: The first sentence of the text.
        :rtype: unicode
        '''
        if stmt is None:
            return None
        text = stmt.arg
        stop_at = text.find('.')
        if stop_at > 0:
            text = text[0:stop_at+1]
        return text

def handler(*names):
    ''' A parameterized decorator to register a Descriptor subclass
    
    :param name: The list of statement names to register for.
    :type names: list-like
    :return: A class decorator.
    '''
    def deco(cls):
        for name in names:
            Descriptor.HANDLER_CLASSES[name] = cls
        return cls
    
    return deco

def arg_or_val(stmt, default=None):
    if stmt is None:
        return default
    return stmt.arg

class Revision(Descriptor):
    ''' Represent a module/submodlue revision item. '''

@handler('module')
class Module(Descriptor):
    ''' Represent a module root node of the tree. '''
    
    def __init__(self, *args, **kwargs):
        Descriptor.__init__(self, *args, **kwargs)
        ctx = kwargs['ctx']
        stmt = kwargs['stmt']
        
        self.organization = arg_or_val(stmt.search_one('organization'))
        self.contact = arg_or_val(stmt.search_one('contact'))
        self.revisions = [Revision(ctx, sub) for sub in stmt.search('revision')]

@handler('typedef')
class Typedef(Descriptor):
    ''' Represent a typedef node in the module tree. '''
    
    def __init__(self, *args, **kwargs):
        Descriptor.__init__(self, *args, **kwargs)
        ctx = kwargs['ctx']
        stmt = kwargs['stmt']
        
        self.type_name = arg_or_val(stmt.search_one('type'))
        if self.type_name is None:
            self.type_uid = None
        else:
            self.type_uid = self._path_uid(ctx._find_typedef(self.type_name))
        self.unit_name = arg_or_val(stmt.search_one('units'))

@handler((MODULE_NAME, 'group'))
class Group(Descriptor):
    ''' Represent a container node in the module tree. '''
    
    def __init__(self, *args, **kwargs):
        Descriptor.__init__(self, *args, **kwargs)

@handler((MODULE_NAME, 'primitive'))
class Primitive(Descriptor):
    ''' Represent a container node in the module tree. '''
    
    def __init__(self, *args, **kwargs):
        Descriptor.__init__(self, *args, **kwargs)

@handler('container')
class Container(Descriptor):
    ''' Represent a container node in the module tree. '''
    
    def __init__(self, *args, **kwargs):
        Descriptor.__init__(self, *args, **kwargs)

@handler('list')
class List(Descriptor):
    ''' Represent a list node in the module tree. '''
    
    def __init__(self, *args, **kwargs):
        Descriptor.__init__(self, *args, **kwargs)
        stmt = kwargs['stmt']
        
        self.key_name = arg_or_val(stmt.search_one('key'))
        self.order_name = arg_or_val(stmt.search_one('order-by'), 'system')
        self.unique_names = [arg_or_val(sub) for sub in stmt.search('unique')]

@handler('notification')
class Notification(Descriptor):
    ''' Represent a notification node in the module tree. '''
    
    def __init__(self, *args, **kwargs):
        Descriptor.__init__(self, *args, **kwargs)
        stmt = kwargs['stmt']

@handler('leaf')
class Leaf(Descriptor):
    ''' Represent a leaf node in the module tree. '''
    
    def __init__(self, *args, **kwargs):
        Descriptor.__init__(self, *args, **kwargs)
        ctx = kwargs['ctx']
        stmt = kwargs['stmt']

        class FirstDefined(object):
            ''' A reducer which captures the first defined sub-statement
            and stops iterating at that point.
            
            The :py:attr:`value` member contains a tuple of:
                1. Unit name
                2. Source name
            '''
            def __init__(self):
                self.value = None
            
            def __call__(self, sub_stmt):
                if sub_stmt is not None:
                    self.value = (sub_stmt.arg, sub_stmt.parent)
                    raise StopIteration
        
        class FirstReadOnly(object):
            def __init__(self):
                self.read_only = False
            
            def __call__(self, stmt):
                if stmt.keyword == 'notification':
                    self.read_only = True
                    raise StopIteration
                
                sub = stmt.search_one('config')
                if sub is None:
                    return
                val = sub.arg
                if val == 'false':
                    self.read_only = True
                    raise StopIteration
        
        self.type_name = stmt.search_one('type').arg
        if self.type_name is None:
            self.type_uid = None
        else:
            self.type_uid = self._path_uid(stmt=ctx._find_typedef(self.type_name))
        self.is_config = (not ctx.walk_tree(stmt, FirstReadOnly()).read_only)
        
        found_unit = ctx.walk_types(stmt, 'units', FirstDefined()).value
        if found_unit is None:
            self.unit_name = None
            self.unit_src = None
        else:
            self.unit_name = found_unit[0]
            self.unit_src = (found_unit[1].arg, self._path_uid(stmt=found_unit[1]))

class DocbookFormatter(pyang.plugin.PyangPlugin):
    ''' An output formatter for a single docbook output tree.
    '''
    
    def add_output_format(self, fmts):
        ''' Register this plugin's output formatters. '''
        fmts['docbook-reference'] = self
    
    def post_validate(self, ctx, modules):
        return pyang.plugin.PyangPlugin.post_validate(self, ctx, modules)
    
    def emit(self, ctx, modules, outfile):
        mod_descriptors = []
        for module in modules:
            mod_ctx = Context(module)
            mod_desc = Module(ctx=mod_ctx, stmt=module)
            mod_descriptors.append(mod_desc)
            #print module.
        
        doc_tmpl = mako.template.Template(text=DOC_TEMPLATE)
        module_tmpl = mako.template.Template(text=MODULE_TEMPLATE)
        toc_item_tmpl = mako.template.Template(text=TOC_ITEM_TEMPLATE)
        detail_item_tmpl = mako.template.Template(text=DETAIL_ITEM_TEMPLATE)
        
        outfile.write(
            doc_tmpl.render(
                mod_descriptors=mod_descriptors,
                module_tmpl=module_tmpl,
                toc_item_tmpl=toc_item_tmpl,
                detail_item_tmpl=detail_item_tmpl,
            )
        )

def pyang_plugin_init():
    ''' Called by plugin framework to initialize this plugin.
    '''
    pyang.plugin.register_plugin(DocbookFormatter())
