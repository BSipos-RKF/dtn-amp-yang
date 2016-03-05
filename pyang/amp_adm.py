
import re
import pyang
from pyang.error import err_add
import logging

logger = logging.getLogger(__name__)

#: Extension module name to hook onto
MODULE_NAME = 'adm-amp'
MODULE_PREFIX = 'amp'

#: Internal type name for OID checking
OID_TYPENAME = 'dotted-oid'
OID_REGEX = re.compile(r'^(0|([1-9]\d*))(\.(0|([1-9]\d*)))*$')

class Ext(object):
    ''' Define an extension schema.
    
    :param keyword: Keyword name.
    :param occurrence: Occurrence flag
    :param typename: Argument type name (or None)
    :param subs: sub-statement keywords
    :param parents: Tuple of: parent-statement keywords, and occurrence flags
    '''
    def __init__(self, keyword, typename, subs, parents):
        self.keyword = keyword
        self.typename = typename
        self.subs = subs
        self.parents = parents

#: may can have absolute or structural OID
any_oid_parents = [('amp:group', '?'),
              ('amp:dataitem', '?'),
              ('amp:report', '?'),
              ('amp:control', '?')]
#: must have absolute OID
abs_oid_parents = [('amp:MID-instance', '1')]
#: List of extension statements defined by the module
MODULE_EXTENSIONS = (
    # Internals
    Ext('amp-type-id', 'uint8', [], [('typedef', '?')]),
    Ext('amp-type-item', 'string', [], [('typedef', '*')]),
    Ext('amp-type-list', 'string', [], [('typedef', '*')]),
    
    #: OID assignment
    Ext('nickname', 'uint8', [], [('module', '*')]),
    Ext('compressoid', OID_TYPENAME, [], any_oid_parents + abs_oid_parents),
    Ext('fulloid', OID_TYPENAME, [], any_oid_parents + abs_oid_parents),
    Ext('suboid', OID_TYPENAME, [], any_oid_parents),
    
    #: Structural items
    Ext('group', 'string', ['amp:group', 'amp:dataitem'],
        [('module', '*')]),
    Ext('dataitem', 'string', ['amp:group'],
        [('amp:group', '*')]),
    Ext('report',  'string', ['amp:reportitem', 'amp:MC-instance'],
        [('amp:group', '*')]),
    Ext('reportitem',  'string', ['amp:MID-instance'],
        [('amp:report', '+')]),
    Ext('control',  'string', ['amp:parameter', 'amp:result'],
        [('amp:group', '*')]),
    Ext('parameter',  'string', ['type'],
        [('amp:report', '*')]),
    Ext('result',  'string', ['type'],
        [('amp:report', '*')]),
    
    #: Instance items
    Ext('MC-instance', None, ['amp:MID-instance'],
        [('amp:report', '?')]),
    Ext('MID-instance', None, ['amp:fulloid', 'amp:compressoid', 'instance-identifier'],
        [('amp:group', '*'), ('amp:dataitem', '*')]),
)

PREFIX_REGEX = re.compile(r'{0}:(.*)'.format(MODULE_PREFIX))
def delprefix(name):
    ''' Remove this module's prefix from names. '''
    match = PREFIX_REGEX.match(name)
    if match is None:
        return name
    return (MODULE_NAME, match.group(1))

def check_oid(val):
    ''' Verify the contents of OID text. '''
    return OID_REGEX.match(val)

def _stmt_set_fulloid(ctx, stmt):
    logger.debug('Search fulloid {0} {1}'.format(stmt.parent.arg, stmt.arg))
    if hasattr(stmt.parent, 'i_dcb_oid'):
        err_add(ctx.errors, stmt.pos, 'AMP_DUPE_OID', ())
        return
    
    oid = [int(dig) for dig in stmt.arg.split('.')]
    stmt.parent.i_dcb_oid = oid
    logger.info('Found fulloid {0}'.format(stmt.parent.i_dcb_oid))

def _find_ancestor_oid(stmt):
    if stmt.parent is None:
        return None
    if hasattr(stmt.parent, 'i_dcb_oid'):
        return stmt.parent.i_dcb_oid
    return _find_ancestor_oid(stmt.parent)

def _stmt_set_suboid(ctx, stmt):
    logger.debug('Search suboid {0} {1}'.format(stmt.parent.arg, stmt.arg))
    if stmt.parent.search_one((MODULE_NAME, 'fulloid')) is not None:
        err_add(ctx.errors, stmt.pos, 'AMP_DUPE_OID', ())
        return
    
    oid = _find_ancestor_oid(stmt.parent)
    if oid is None:
        err_add(ctx.errors, stmt.pos, 'AMP_BAD_SUBID', ())
        return
    stmt.parent.i_dcb_oid = oid + [int(stmt.arg)]
    logger.info('Found suboid {0}'.format(stmt.parent.i_dcb_oid))
    
    as_text = '.'.join([str(dig) for dig in stmt.parent.i_dcb_oid])
    sub = pyang.statements.Statement(top=stmt.top, parent=stmt, pos=None, keyword=(MODULE_NAME, 'fulloid'), arg=as_text)
    stmt.parent.substmts.append(sub)

def pyang_plugin_init():
    ''' Called by plugin framework to initialize this plugin.
    '''
    #logging.basicConfig(level=logging.DEBUG, stream=sys.stderr)
    
    # Register that we handle extensions from the associated YANG module
    pyang.grammar.register_extension_module(MODULE_NAME)
    pyang.syntax.add_arg_type(OID_TYPENAME, check_oid)
    
    # These are missing from pyang
    #pyang.grammar.add_stmt('default', ('string', []))
    pyang.grammar.add_stmt('instance-identifier', ('string', []))
    
    for ext in MODULE_EXTENSIONS:
        sub_stmts = [delprefix(name) for name in ext.subs]
        #print ext.keyword, ext.typename, sub_stmts
        pyang.grammar.add_stmt((MODULE_NAME, ext.keyword), (ext.typename, sub_stmts))
    for ext in MODULE_EXTENSIONS:
        for (name, occurr) in ext.parents:
            pyang.grammar.add_to_stmts_rules([delprefix(name)], [((MODULE_NAME, ext.keyword), occurr)])
    
    # Add validation step
    pyang.statements.add_validation_phase('set_oid', after='inherit_properties')
    pyang.statements.add_validation_fun(
        'type_2',
        [(MODULE_NAME, 'fulloid')],
        _stmt_set_fulloid
    )
    pyang.statements.add_validation_fun(
        'type_2',
        [(MODULE_NAME, 'suboid')],
        _stmt_set_suboid
    )
    # Register special error codes
    pyang.error.add_error_code('AMP_BAD_SUBID', 1,
                         "subid needs an oid or subid statement in an ancestor")
    pyang.error.add_error_code('AMP_DUPE_OID', 1,
                         "subid and oid cannot be given at the same time")
