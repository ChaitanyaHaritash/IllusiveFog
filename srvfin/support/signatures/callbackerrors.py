#Module handle error codes of plugins

errors_dict = {
    'shell':{
        '0' : 'Success'
    },
    'SelfSocks5' : {
        '0' : 'Success',
        '-1' :'Server Address Set',
        '-2' :'Server Port Set',
        '-3' :'server ws startup',
        '-4' :'server invalid socket',
        '-5' :'port in use',
        '-6' :'failed to bind',
        '-7' :'failed to listen'
    },
    'injShellcode' : {
        '0' :'Sucess',
        '-1' : 'Failed'
    },
    'EVTX' : {
       '-22':'Inavlid Parameters',
       '-23':'Failed Export File',
       '-24':'EVTX File Handle Invalid',
       '-25':'Invalid Handle'
    },
    'ETW' : {
        '-32':'Error String From CLSID Failed',
        '-33':'Error provider enumeration info realloc Failed',
        '-30':'Error Invalid Parameter',
        '-31':'Error no plugin initialized',
        '-34':'Error Invalid GUID',
        '-35':'Tracing Session Access Denied'
    },
    'VerboseRecon': {
        '0':'verbose mitig success',
        '-51':'process mitigs failed',
        '-52':'process dep enabled',
        '-53':'process dep disabled',
        '-54':'process dep permenant',
        '-55':'process dep temporary',
        '-56':'process dep disable atl thunk emulation',
        '-57':'process dep enable atl thunk emulation',
        '-58':'process bottom up aslr enabled',
        '-59':'process bottom up aslr disabled',
        '-60':'process aslr enable force relocate image',
        '-61':'process aslr disable force relocate image',
        '-62':'process aslr enable high entropy',
        '-63':'process aslr disable high entropy',
        '-64':'process disallow stripped image',
        '-65':'process allow stripped image',
        '-66':'process dyn code prohibited',
        '-68':'process dyn code allowed',
        '-69':'process dyn code allow thread opt out',
        '-70':'process dyn code disallow thread opt out',
        '-71':'process dyn code allow remote downgrade',
        '-72':'process dyn code disallow remote downgrade',
        '-73':'process handle check generate exception invalid handle',
        '-74':'process handle check inv handle generate exception disable',
        '-75':'process handle check inv handle usage ignored',
        '-76':'process syscall win32k syscalls blocked audited',
        '-97':'process syscall win32k syscalls blocked',
        '-77':'process syscall win32k syscalls allowed',
        '-78':'process legacy dll extension points disabled',
        '-79':'process legacy dll extension points enabled',
        '-80':'process cfg enabled',
        '-81':'process cfg disabled',
        '-82':'process cfg export functions indirect calls disalled',
        '-98':'process cfg export functions indirect calls allowed',
        '-83':'process cfg strict enabled',
        '-84':'process cfg strict disabled',
        '-85':'process bin sig policy signed only',
        '-86':'process bin sig policy store sign only',
        '-87':'process bin sig policy whql sign only',
        '-88':'process bin sig policy arbitrary',
        '-89':'process system font only',
        '-90':'process arbitrary font',
        '-91':'process image policy no remote image',
        '-92':'process image policy remote image allowed',
        '-93':'process image policy load image lowil prohibited',
        '-94':'process image policy load image arbitrary il',
        '-95':'process image policy prefer system32 image',
        '-96':'process image policy basic image search'
    },
    'persistence' : {
        'To be defined' : 'To be defined'
    },
    'Loader' : {
        '-41':'Failed Write',
        '-42':'Failed pipe_write',
        '-40':'Failed spawn process',
        '0':'Success'
    },
    'Pellet':{
        '0':'pellet_ec_code_success',
        '-26':'pellet_ec_failed_get_file',
        '-27':'pellet_ec_failed_crypt_pellet_failed',
        '-28':'pellet_ec_get_pellet_failed',
        '-29':'pellet_set_info_failed'
    },
     'Plugin':{
        '-5' : 'IllusiveFog_post_request_heap_corrupted',
        '-6' : 'IllusiveFog_no_intial_params',
        '-7' : 'form_agent_session_heap_corrupted',
        '-8' : 'IllusiveFog_get_agent_info_failed',
        '-9' : 'set_agent_session_info_error',
        '-10' : 'IllusiveFog_heap_corrupted_receive_jobs',
        '-11' : 'IllusiveFog_error_no_job_received',
        '-12' : 'IllusiveFog_error_plugin_already_loaded',
        '-13' : 'IllusiveFog_error_invalid_heap_allocated',
        '-14' : 'IllusiveFog_error_failed_send_agent_info',
        '-15' : 'IllusiveFog_error_form_hex_command_failed',
        '-16' : 'IllusiveFog_error_form_agent_requirements_failed',
        '-17' : 'IllusiveFog_error_plugin_load_failed',
        '-18' : 'IllusiveFog_error_plugin_parse_failed',
        '-19' : 'IllusiveFog_error_plugin_set_failed',
        '-20' : 'IllusiveFog_error_plugin_unset_failed',
        '-21' : 'IllusiveFog_error_IllusiveFog_invoke_plugin_failed',
        '-22' : 'IllusiveFog_error_agent_plugin_req_failed',
        '-23' : 'IllusiveFog_error_plugin_unloaded',
        '-24' : 'IllusiveFog_error_no_jobs',
        '-25' : 'IllusiveFog_agent_crashed'
     }   
}

def matchError(ecs):
    for i in errors_dict.items():
        for g in errors_dict[i[0]].iteritems():
            if ecs in g[0]:
                return [g[1],g[0]]