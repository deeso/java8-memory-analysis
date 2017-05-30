def convert_json_map(json_obj):
    result = {}
    table = None
    if json_obj is None:
        return None
    if 'org/json/JSONObject' in json_obj.oop_field_values_by_name and 'map' in json_obj.oop_field_values_by_name['org/json/JSONObject']:
        m = json_obj.oop_field_values_by_name['org/json/JSONObject']['map']
        if m is None:
            return None
        table = m.oop_field_values_by_name['java/util/HashMap']['table']

    if table is None:
        return None
    
    for node in table.oop_values:
        if node is None:
            continue
        key = node.get_oop_field_value('key')
        value = node.oop_field_values_by_name['java/util/HashMap$Node']['value']
        result[key] = convert_json_obj(value)
        
    return result

def convert_json_obj(json_obj):
    if json_obj is None:
        return None
    if 'org/json/JSONObject' in json_obj.oop_field_values_by_name and\
       'map' in json_obj.oop_field_values_by_name['org/json/JSONObject']:
        return convert_json_map(json_obj)
    elif 'org/json/JSONArray' in json_obj.oop_field_values_by_name and \
        'myArrayList' in json_obj.oop_field_values_by_name['org/json/JSONArray']:
        return convert_json_array(json_obj)
    else:
        try:
            return json_obj.get_oop_field_value('value')
        except:
            print ("Failed to convert Json value")
            return None
                

def convert_json_array(json_obj):
    if json_obj is None:
        return None
    result = []
    alist = None
    if 'org/json/JSONArray' in json_obj.oop_field_values_by_name and \
       'myArrayList' in json_obj.oop_field_values_by_name['org/json/JSONArray']:
        _list = json_obj.oop_field_values_by_name['org/json/JSONArray']['myArrayList']
        if _list is None:
            return None
        elif not 'java/util/ArrayList' in _list.oop_field_values_by_name or \
             not 'elementData' in _list.oop_field_values_by_name['java/util/ArrayList']:
             return None
        alist = _list.oop_field_values_by_name['java/util/ArrayList']['elementData']
    
    for node in alist.oop_values:
        if node is None:
            continue
        result.append(convert_json_obj(node))
    return result
