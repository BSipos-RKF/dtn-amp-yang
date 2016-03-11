
import re
import pyang
from pyang.error import err_add
import logging

logger = logging.getLogger(__name__)

#: Extension module name to hook onto
MODULE_NAME = 'amp-adm'
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
    def __init__(self, keyword, typename, subs=None, parents=None, **kwargs):
        self.keyword = keyword
        self.typename = typename
        if subs is None:
            subs = []
        self.subs = subs
        if parents is None:
            parents = []
        self.parents = parents
        self.has_description = True
        for (key,val) in kwargs.iteritems():
            setattr(self, key, val)

#: may can have absolute or structural OID
any_oid_parents = [((MODULE_NAME, 'group'), '?'),
                   ((MODULE_NAME, 'primitive'), '?'),
                   ((MODULE_NAME, 'report'), '?'),
                   ((MODULE_NAME, 'control'), '?'),
                   ('container', '?'),
                   ('list', '?'),
                   ('leaf', '?')]
#: List of extension statements defined by the module
MODULE_EXTENSIONS = (
    # Internals
    Ext('amp-type-id', 'uint8', [], parents=[('typedef', '?')]),
    Ext('amp-type-item', 'string', [], parents=[('typedef', '*')]),
    Ext('amp-type-list', 'string', [], parents=[('typedef', '*')]),
    
    #: OID assignment
    Ext('nickname', 'uint8',
        subs=[((MODULE_NAME, 'fulloid'), '1')],
        parents=[('module', '*')]),
    Ext('compressoid', OID_TYPENAME, [], 
        parents=(any_oid_parents)),
    Ext('fulloid', OID_TYPENAME, [],
        parents=(any_oid_parents + [('module', '?')])),
    Ext('suboid', OID_TYPENAME, [],
        parents=any_oid_parents),
    
    #: Structural items
    Ext('group', 'string',
        subs=[((MODULE_NAME, 'group'), '*'),
              ('list', '*')],
        parents=[('module', '*')]),
    
    Ext('primitive', 'string',
        subs=[('type', '1')],
        parents=[('container', '*'),
                 ((MODULE_NAME, 'group'), '*')]),
    Ext('computed', 'string',
        subs=[('type', '1')],
        parents=[('container', '*'),
                 ((MODULE_NAME, 'group'), '*')]),
    
    Ext('report', 'string',
        subs=[((MODULE_NAME, 'reportitem'), '*'),
              ((MODULE_NAME, 'MC-instance'), '?')],
        parents=[((MODULE_NAME, 'group'), '*')]),
    Ext('reportitem', 'string',
        subs=[(MODULE_NAME, 'MID-instance')]),
    
    Ext('control', 'string',
        subs=[((MODULE_NAME, 'parameter'), '*'),
              ((MODULE_NAME, 'result'), '*')],
        parents=[((MODULE_NAME, 'group'), '*')]),
    Ext('parameter', 'string',
        subs=[('type', '1')]),
    Ext('result', 'string',
        subs=[('type', '1')]),
    
    #: Instance items
    Ext('instance-text', 'string'),
    Ext('primitive-instance', None,
        subs=[('type', '1'),
              ((MODULE_NAME, 'instance-text'), '?')]),
    Ext('issuer-instance', 'sdnv'),
    Ext('tag-instance', 'sdnv'),
    
    Ext('MID-instance', None,
        subs=[((MODULE_NAME, 'fulloid'), '?'),
              ((MODULE_NAME, 'compressoid'), '?'),
              ('instance-identifier', '?'),
              ((MODULE_NAME, 'primitive-instance'), '?')],
        parents=[((MODULE_NAME, 'group'), '*'),
                 ((MODULE_NAME, 'primitive'), '*'),
                 ((MODULE_NAME, 'computed'), '*')]),
    Ext('MC-instance', None,
        subs=[((MODULE_NAME, 'MID-instance'), '*')],
        parents=[((MODULE_NAME, 'report'), '?')]),
)

def check_uint8(val):
    ''' Verify numeric statement argument. '''
    try:
        val = int(val)
        return (val >= 0 and val <= 255)
    except TypeError:
        return False

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
    pyang.syntax.add_arg_type('uint8', check_uint8)
    pyang.syntax.add_arg_type(OID_TYPENAME, check_oid)
    
    for ext in MODULE_EXTENSIONS:
        sub_stmts = ext.subs
        #print ext.keyword, ext.typename, sub_stmts
        pyang.grammar.add_stmt((MODULE_NAME, ext.keyword), (ext.typename, sub_stmts))
    for ext in MODULE_EXTENSIONS:
        for (name, occurr) in ext.parents:
            pyang.grammar.add_to_stmts_rules([name], [((MODULE_NAME, ext.keyword), occurr)])
        
        # Standard substatements
        if ext.has_description:
            pyang.grammar.add_to_stmts_rules([(MODULE_NAME, ext.keyword)], [('description', '?')])
    
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
