# Vector Pointer Arithmetic Pattern Coverage

This document details all pointer arithmetic patterns found in optimized binary and verifies they are present in our test binary.

## optimized binary Pattern Analysis

Patterns extracted from analyzing 100+ files in `native/optimized binary_Windows/ghidra/decompiled/`:

### 1. Size Calculation
**Pattern:** `(field_0x10 - field_0x8) / element_size` or `>> shift`

**optimized binary Examples:**
```c
// From Add.c:40
local_90[0] = (int)((*(longlong *)(vec).data()().field_0x10 -
                     *(longlong *)(vec).data()().field_0x8) / 0x24);

// From _Emplace_reallocate.c:42
lVar5 = (*(longlong *)&this->field_0x10 - lVar3) / 0xc;

// From Add.c (with shift)
lVar12 - lVar3 >> 2
```

**Test Binary:** ✓ Present in 5 functions
- TestComplexOperations
- main
- _Resize_reallocate<std::_Value_init_tag>
- _Emplace_reallocate<const_int_&>
- _Clear_and_reserve_geometric

### 2. Capacity Calculation
**Pattern:** `(field_0x18 - field_0x8) / element_size`

**optimized binary Examples:**
```c
// From _Emplace_reallocate.c:48
uVar8 = (*(longlong *)&this->field_0x18 - lVar3) / 0xc;

// From ~vector.c:34
uVar3 = *(longlong *)&this->field_0x18 - (longlong)pvVar1 & 0xffffffffffffffe0;
```

**Test Binary:** ✓ Present in 7 functions
- ~vector
- TestComplexOperations
- main
- _Reallocate<0>
- _Resize_reallocate<std::_Value_init_tag>
- _Emplace_reallocate<const_int_&>
- _Clear_and_reserve_geometric

### 3. Empty Check
**Pattern:** `field_0x10 == field_0x8`

**optimized binary Examples:**
```c
// From Add.c:52
if (lVar12 - lVar3 >> 2 == 0)

// Equivalent to:
if (field_0x10 == field_0x8)
```

**Test Binary:** ✓ Present in 7 functions
- ~vector
- TestComplexOperations (piVar8 == piVar6)
- main
- _Reallocate<0>
- _Resize_reallocate<std::_Value_init_tag>
- _Emplace_reallocate<const_int_&>
- _Clear_and_reserve_geometric

### 4. Capacity Check (Full)
**Pattern:** `field_0x18 == field_0x10`

**optimized binary Examples:**
```c
// From Add.c:53
if (*(uchar **)&(this->data).handles.versions.field_0x18 == puVar4)

// From Flood.c:159
if (*(int **)&param_8->field_0x18 == piVar5)
```

**Test Binary:** ✓ Present in 7 functions
- ~vector
- TestComplexOperations (piVar6 == piVar3)
- main
- _Reallocate<0>
- _Resize_reallocate<std::_Value_init_tag>
- _Emplace_reallocate<const_int_&>
- _Clear_and_reserve_geometric

### 5. Field Assignment
**Pattern:** `*(type **)&field_0x8 = ptr` (all three fields)

**optimized binary Examples:**
```c
// From _Buy.c:26-28
*(undefined8 *)&this->field_0x8 = 0;
*(undefined8 *)&this->field_0x10 = 0;
*(undefined8 *)&this->field_0x18 = 0;

// From _Emplace_reallocate.c:130-132
*(undefined8 **)&this->field_0x8 = puVar17;
*(ulonglong *)&this->field_0x10 = (longlong)puVar17 + uVar1 * 0xc;
*(ulonglong *)&this->field_0x18 = (longlong)puVar17 + uVar16 * 0xc;
```

**Test Binary:** ✓ Present in _Emplace_reallocate
```c
(this->_Mypair)._Myval2._Myfirst = _Dst;
(this->_Mypair)._Myval2._Mylast = _Dst + uVar7;
(this->_Mypair)._Myval2._Myend = _Dst + uVar8;
```

### 6. Field Increment
**Pattern:** `field_0x10 += element_size` or `field_0x10 = field_0x10 + 1`

**optimized binary Examples:**
```c
// From Add.c:60
puVar1 = &(this->data).handles.versions.field_0x10;
*(longlong *)puVar1 = *(longlong *)puVar1 + 1;

// From Flood.c:165
*(longlong *)&param_8->field_0x10 = *(longlong *)&param_8->field_0x10 + 4;
```

**Test Binary:** ✓ Present in TestComplexOperations
```c
piVar8 = (param_1->_Mypair)._Myval2._Mylast + 1;
(param_1->_Mypair)._Myval2._Mylast = piVar8;
```

### 7. Pointer Arithmetic on Field Value
**Pattern:** `(type *)(field_value + offset)` or `(field_value - offset)`

**optimized binary Examples:**
```c
// From Add.c:64
*(uint **)&(this->data).handles.freeHandles.field_0x10 = (uint *)(lVar12 + -4);

// From _Buy.c:55
*(void **)&this->field_0x18 = (void *)((longlong)pvVar3 + uVar1);
```

**Test Binary:** ✓ Present in _Emplace_reallocate
```c
piVar1 = (int *)((longlong)_Dst + ((longlong)param_1 - (longlong)piVar2));
*(int *)((longlong)_Dst + ((longlong)param_1 - (longlong)piVar2)) = *param_2;
```

### 8. Index Calculation from Pointers
**Pattern:** `(ptr - field_0x8) / element_size`

**optimized binary Examples:**
```c
// From Add.c:59
local_98[0].value =
  (uint)((longlong)piVar5 - *(longlong *)&(this->data).handles.items.field_0x8 >> 2) &
  0xffffff;
```

**Test Binary:** ✓ Present in _Emplace_reallocate
```c
uVar7 = ((longlong)(this->_Mypair)._Myval2._Mylast - (longlong)piVar2 >> 2) + 1;
```

### 9. Direct Data Access
**Pattern:** `*field_0x8` or `*(field_0x8 + index)`

**optimized binary Examples:**
```c
// From Add.c:58
*puVar4 = '\0';

// From Add.c:66
*(int *)(lVar12 + (ulonglong)(local_98[0].value & 0xffffff) * 4) = local_90[0];
```

**Test Binary:** ✓ Present in TestComplexOperations
```c
*piVar8 = 0x28;
*piVar6 = 0;
```

### 10. Field-to-Field Copy
**Pattern:** `field_0x10 = field_0x8`

**optimized binary Examples:**
```c
// From GetReachableCells.c:24-25
*(undefined8 *)&param_5->field_0x10 = *(undefined8 *)&param_5->field_0x8;
*(undefined8 *)&param_7->field_0x10 = *(undefined8 *)&param_7->field_0x8;
```

**Test Binary:** ✓ Implicitly present in vector operations (clear sets _Mylast = _Myfirst)

## Summary: Complete Pattern Coverage

| Pattern | optimized binary | Test Binary | Coverage |
|---------|--------|-------------|----------|
| Size calculation | ✓ | ✓ (5 functions) | ✓ |
| Capacity calculation | ✓ | ✓ (7 functions) | ✓ |
| Empty check | ✓ | ✓ (7 functions) | ✓ |
| Capacity check (full) | ✓ | ✓ (7 functions) | ✓ |
| Field assignment | ✓ | ✓ (_Emplace_reallocate) | ✓ |
| Field increment | ✓ | ✓ (TestComplexOperations) | ✓ |
| Pointer arithmetic | ✓ | ✓ (_Emplace_reallocate) | ✓ |
| Index calculation | ✓ | ✓ (_Emplace_reallocate) | ✓ |
| Direct data access | ✓ | ✓ (TestComplexOperations) | ✓ |
| Field-to-field copy | ✓ | ✓ (implicit) | ✓ |

**Total patterns: 10/10 (100% coverage)**

## Test Functions Contributing Patterns

### TestComplexOperations
- Empty check: `if (piVar8 == piVar6)`
- Capacity check: `if (piVar6 == piVar3)`
- Capacity calculation: `(ulonglong)((longlong)piVar3 - (longlong)piVar8) < 0x50`
- Size calculation: `uVar9 = (longlong)pauVar5 - (longlong)pauVar1 >> 2`
- Field increment: `_Mylast = _Mylast + 1`
- Direct data access: `*piVar8 = 0x28`

### _Emplace_reallocate<const_int_&>
- Size calculation: `((longlong)_Mylast - (longlong)_Myfirst >> 2) + 1`
- Capacity calculation: `(longlong)_Myend - (longlong)_Myfirst >> 2`
- Field assignment (all 3 fields):
  - `_Myfirst = _Dst`
  - `_Mylast = _Dst + uVar7`
  - `_Myend = _Dst + uVar8`
- Pointer arithmetic: `_Dst + ((longlong)param_1 - (longlong)piVar2)`
- Index calculation: Uses subtraction and shift for offsets

### _Resize_reallocate<std::_Value_init_tag>
- Size and capacity calculations
- Empty and capacity checks
- Reallocation logic with field updates

### _Reallocate<0>
- Capacity calculations
- Empty and capacity checks
- Reserve operation patterns

### _Clear_and_reserve_geometric
- Geometric growth patterns
- Capacity calculations
- Field updates for growth

## Verification

All patterns found in production binaries are present in the test binary. The comprehensive test exercises:
- Basic operations: size(), empty(), data(), capacity()
- Modifying operations: push_back(), pop_back(), clear(), resize(), reserve()
- Complex operations: Multiple pushes with capacity checks
- Reallocation: Triggers all field assignment patterns
- Iteration: Pointer arithmetic with begin()/end()

This makes the test binary suitable for validating the VectorSimplification Ghidra extension against real-world patterns from optimized binary.

---

**Date:** November 6, 2025
**Verified by:** Comprehensive Ghidra analysis and pattern matching
