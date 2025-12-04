# EpiCompiler Test Suite

This directory contains a comprehensive test suite for the TheShowLang (TSLang) compiler.

## Directory Structure

```
tests/
├── README.md                    # This file
├── run_tests.sh                 # Test runner script
│
├── 01-30 (root tests)          # Basic feature tests
│   ├── 01_basic_hello_world.tslang
│   ├── 02-04: Variable tests (int, float, string)
│   ├── 05-07: Arithmetic tests (basic, complex, compound)
│   ├── 08: Comparison operators
│   ├── 09-10: Conditionals (basic, nested)
│   ├── 11-14: Loops (for, while, nested, break/continue)
│   ├── 15-16: Functions (basic, recursive)
│   ├── 17-20: Arrays (1D, 2D, 3D, with functions)
│   ├── 21-22: Pointers (basic, with functions)
│   ├── 23-25: Structures (basic, with functions, arrays)
│   ├── 26-27: Constants and Enums
│   ├── 28: String interpolation
│   ├── 29: Comments
│   └── 30: Return values
│
├── errors/                      # Error handling tests (should fail)
│   ├── err_01_missing_type.tslang
│   ├── err_02_missing_return_type.tslang
│   ├── err_03_missing_paren_condition.tslang
│   ├── err_04_missing_colon.tslang
│   ├── err_05_unclosed_paren.tslang
│   ├── err_06_unclosed_string.tslang
│   ├── err_07_invalid_keyword.tslang
│   ├── err_08_missing_operand.tslang
│   ├── err_09_else_without_if.tslang
│   ├── err_10_empty_condition.tslang
│   ├── err_11_mismatched_brackets.tslang
│   ├── err_12_bad_indentation.tslang
│   ├── err_13_peric_no_paren.tslang
│   ├── err_14_for_missing_in.tslang
│   ├── err_15_for_missing_range.tslang
│   ├── err_16_invalid_assignment.tslang
│   ├── err_17_return_no_value.tslang
│   └── err_18_unclosed_char.tslang
│
├── edge/                        # Edge case tests
│   ├── edge_01_zero_negative.tslang
│   ├── edge_02_large_numbers.tslang
│   ├── edge_03_strings.tslang
│   ├── edge_04_loop_boundaries.tslang
│   ├── edge_05_functions.tslang
│   └── edge_06_conditionals.tslang
│
├── stress/                      # Stress tests
│   ├── stress_01_deep_recursion.tslang
│   ├── stress_02_large_loops.tslang
│   ├── stress_03_many_variables.tslang
│   ├── stress_04_many_functions.tslang
│   ├── stress_05_large_arrays.tslang
│   └── stress_06_complex_expressions.tslang
│
├── algorithms/                  # Algorithm implementations
│   ├── algo_01_bubble_sort.tslang
│   ├── algo_02_selection_sort.tslang
│   ├── algo_03_binary_search.tslang
│   ├── algo_04_gcd_lcm.tslang
│   ├── algo_05_primes.tslang
│   └── algo_06_reverse.tslang
│
└── integration/                 # Integration tests
    ├── integ_01_calculator.tslang
    ├── integ_02_student_management.tslang
    ├── integ_03_inventory.tslang
    └── integ_04_game_score.tslang
```

## Test Categories

### Basic Tests (01-30)
Tests for individual language features:
- Variables (int, float, string)
- Arithmetic operations
- Comparison operators
- Control flow (if/else, loops)
- Functions and recursion
- Arrays (1D, 2D, 3D)
- Pointers and references
- Structures
- Constants and Enums
- Comments

### Error Tests (errors/)
Tests that should produce compiler errors:
- Syntax errors
- Missing tokens
- Invalid keywords
- Unclosed delimiters
- Bad indentation

### Edge Case Tests (edge/)
Tests for boundary conditions:
- Zero and negative numbers
- Large numbers
- Empty strings
- Loop boundaries
- Function edge cases

### Stress Tests (stress/)
Tests for performance and limits:
- Deep recursion
- Large iteration counts
- Many variables/functions
- Complex expressions

### Algorithm Tests (algorithms/)
Classic algorithm implementations:
- Sorting (bubble, selection)
- Searching (binary search)
- Math (GCD, LCM, primes)
- Array manipulation

### Integration Tests (integration/)
Complete programs using multiple features:
- Calculator
- Student management
- Inventory system
- Game score system

## Running Tests

### Run all tests:
```bash
./run_tests.sh
```

### Run specific category:
```bash
./run_tests.sh basic     # Run basic tests only
./run_tests.sh errors    # Run error tests only
./run_tests.sh edge      # Run edge case tests
./run_tests.sh stress    # Run stress tests
./run_tests.sh algo      # Run algorithm tests
./run_tests.sh integ     # Run integration tests
```

### Run single test:
```bash
../EpiCompiler tests/01_basic_hello_world.tslang
```

## Expected Results

- **Basic tests**: Should all compile and run successfully
- **Error tests**: Should all produce compilation errors
- **Edge tests**: Should handle boundary conditions correctly
- **Stress tests**: Should complete without crashes
- **Algorithm tests**: Should produce correct results
- **Integration tests**: Should demonstrate complete feature usage

## Adding New Tests

1. Create a new `.tslang` file in the appropriate directory
2. Add a comment header describing the test:
   ```
   desnote ========================================
   desnote TEST: [Test Name]
   desnote Tests: [What this tests]
   desnote Expected: [Expected behavior]
   desnote ========================================
   ```
3. Implement the test
4. Update this README if adding a new category

## Language Features Tested

| Feature | Test Files |
|---------|------------|
| Hello World | 01 |
| Int variables | 02 |
| Float variables | 03 |
| String variables | 04, 28 |
| Arithmetic | 05, 06, 07 |
| Comparisons | 08 |
| If/Else | 09, 10 |
| For loops | 11, 13 |
| While loops | 12, 13 |
| Break/Continue | 14 |
| Functions | 15, 16 |
| Recursion | 16 |
| 1D Arrays | 17, 20 |
| 2D Arrays | 18 |
| 3D Arrays | 19 |
| Pointers | 21, 22 |
| Structures | 23, 24, 25 |
| Constants (cz) | 26 |
| Enums (desnum) | 27 |
| Comments (desnote) | 29 |
| Return values | 30 |
