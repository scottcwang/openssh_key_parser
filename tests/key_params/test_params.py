import pytest
from openssh_key.pascal_style_byte_stream import PascalStyleFormatInstruction

import test_dss
import test_ecdsa
import test_ed25519
import test_rsa

_TEST_CASES = sum(
    [
        test_rsa.PARAMS_TEST_CASES,
        test_ed25519.PARAMS_TEST_CASES,
        test_dss.PARAMS_TEST_CASES,
        test_ecdsa.PARAMS_TEST_CASES,
    ],
    []
)


@pytest.mark.parametrize('key_params_test', _TEST_CASES)
def test_format_instructions_dict(key_params_test):
    assert key_params_test['cls'].FORMAT_INSTRUCTIONS_DICT \
        == key_params_test['format_instructions_dict']


@pytest.mark.parametrize('key_params_test', _TEST_CASES)
def test_params_are_valid(key_params_test):
    for valid_value in key_params_test['valid_values']:
        key_params_object = key_params_test['cls'](valid_value)
        with pytest.warns(None) as warnings_list:
            key_params_object.check_params_are_valid()
        assert not warnings_list


@pytest.mark.parametrize('key_params_test', _TEST_CASES)
def test_extra_params_are_valid(key_params_test):
    for valid_value in key_params_test['valid_values']:
        mutated_value = dict(valid_value)
        mutated_value['nonexistent'] = 1
        key_params_object = key_params_test['cls'](mutated_value)
        with pytest.warns(None) as warnings_list:
            key_params_object.check_params_are_valid()
        assert not warnings_list


@pytest.mark.parametrize('key_params_test', _TEST_CASES)
def test_missing_params_are_not_valid(key_params_test):
    for valid_value in key_params_test['valid_values']:
        for k in valid_value:
            mutated_value = dict(valid_value)
            del mutated_value[k]
            with pytest.warns(UserWarning, match=(k + ' missing')):
                key_params_object = key_params_test['cls'](mutated_value)
            with pytest.warns(UserWarning, match=(k + ' missing')):
                key_params_object.check_params_are_valid()


@pytest.mark.parametrize('key_params_test', _TEST_CASES)
def test_bad_type_params_are_not_valid(key_params_test):
    for valid_value in key_params_test['valid_values']:
        for k in valid_value:
            expected_type = key_params_test['format_instructions_dict'][k]
            for mutated_type in PascalStyleFormatInstruction:
                if expected_type == mutated_type:
                    continue
                mutated_value = dict(valid_value)
                mutated_value[k] = (mutated_type.value)()
                expected_warning_message = k + ' should be of class ' \
                    + expected_type.value.__name__
                with pytest.warns(UserWarning, match=expected_warning_message):
                    key_params_object = key_params_test['cls'](mutated_value)
                with pytest.warns(UserWarning, match=expected_warning_message):
                    key_params_object.check_params_are_valid()


@pytest.mark.parametrize('key_params_test', _TEST_CASES)
def test_invalid_params_are_not_valid(key_params_test):
    if 'invalid_values' not in key_params_test:
        return
    for invalid_value, expected_warning_message \
            in key_params_test['invalid_values']:
        with pytest.warns(UserWarning, match=expected_warning_message):
            key_params_object = key_params_test['cls'](invalid_value)
        with pytest.warns(UserWarning, match=expected_warning_message):
            key_params_object.check_params_are_valid()


@pytest.mark.parametrize('key_params_test', _TEST_CASES)
def test_equals_dict(key_params_test):
    for valid_value in key_params_test['valid_values']:
        key_params_object = key_params_test['cls'](valid_value)
        assert key_params_object == valid_value
