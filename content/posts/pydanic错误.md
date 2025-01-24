

+++
title = "Pydantic 错误集锦"
date = 2025-01-24
updated = 2025-01-24
[taxonomies]
categories = ["Python Tips"]
tags = ["python","Pydantic"]
[extra]
lang = "zh"
toc = true
comment = true
math = true
mermaid = true
+++


## Pydantic mistakes 集锦

### Missing错误

pydanic从1更新到2出现了一些毛病，这里对其进行说明。

```python 
from pydantic import BaseModel, field_validator

class Config(BaseModel):
    weather_api_key: str = "111"
    weather_command_priority: int = 10
    weather_plugin_enabled: bool = True

    @field_validator("weather_command_priority")
    @classmethod
    def check_priority(cls, v: int) -> int:
        if v >= 1:
            return v
        raise ValueError("weather command priority must greater than 1")
```

比如这个代码，如果不对每个参数进行赋初值的话将会报错：

```shell
pydantic_core._pydantic_core.ValidationError: 1 validation error for Config
weather_api_key
  Field required [type=missing, input_value={'driver': '~fastapi', 'h...), 'environment': 'dev'}, input_type=dict]
    For further information visit https://errors.pydantic.dev/2.10/v/missing
```

因为更新到2.x版本后不能用缺省的None了

参考:[pydantic v1 迁移到 v2 需要注意的事项 - python后端实战经验分享 - SegmentFault 思否](https://segmentfault.com/a/1190000044459293)

