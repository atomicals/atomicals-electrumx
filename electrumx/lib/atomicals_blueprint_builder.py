from electrumx.lib.util_atomicals import (
    is_compact_atomical_id, 
    parse_protocols_operations_from_witness_array, 
    get_nominal_token_value
)

def get_highest_exponent(atomicals_array):
    max = 0
    for entry in atomicals_array:
        if max < entry['exponent']:
            max = entry['exponent']
    return max

def get_nominal_token_value(value, exponent):
    assert(value >= 0)
    assert(exponent >= 0)
    return value / (10**exponent)

def get_adjusted_sats_needed_by_exponent(value, target_exponent):
    return value * (10**exponent)

def get_token_satoshi_exponent_values(ft_info):
    accumulated_token_value = 0
    highest_exponent = get_highest_exponent(ft_info['input_indexes'])
    for entry in ft_info['input_indexes']: 
        current_input_exponent = entry['exponent']
        accumulated_token_value += get_nominal_token_value(ft_info['value'], entry['exponent'])
    sats_needed = get_adjusted_sats_needed_by_exponent(accumulated_token_value, highest_exponent)
    return accumulated_token_value, sats_needed, highest_exponent

def calculate_outputs_to_color_for_ft_atomical_ids(ft_atomicals, sort_by_fifo):
    num_fts = len(ft_atomicals.keys())
    if num_fts == 0:
        return None, None, None
    atomical_list = order_ft_inputs(ft_atomicals, sort_by_fifo)
    next_start_out_idx = 0
    potential_atomical_ids_to_output_idxs_map = {}
    non_clean_output_slots = False
    for item in atomical_list:
      atomical_id = item['atomical_id']
      token_value, expected_satoshi_value, highest_exponent = get_token_satoshi_exponent_values(item['ft_info'])
      cleanly_assigned, expected_outputs = assign_expected_outputs_basic(atomical_id, expected_satoshi_value, tx, next_start_out_idx)
      if cleanly_assigned and len(expected_outputs) > 0:
        next_start_out_idx = expected_outputs[-1] + 1
        potential_atomical_ids_to_output_idxs_map[atomical_id] = {
          'expected_outputs': expected_outputs,
          'exponent': highest_exponent
        }
      else:
        # Erase the potential for safety
        potential_atomical_ids_to_output_idxs_map = {}
        non_clean_output_slots = True
        break
  
    # If the output slots did not fit cleanly, then default to just assigning everything from the 0'th output index
    if non_clean_output_slots:
      potential_atomical_ids_to_output_idxs_map = {}
      for item in atomical_list:
        atomical_id = item['atomical_id']
        token_value, expected_satoshi_value, highest_exponent = get_token_satoshi_exponent_values(item['ft_info'])
        cleanly_assigned, expected_outputs = assign_expected_outputs_basic(atomical_id, expected_satoshi_value, tx, 0)
        potential_atomical_ids_to_output_idxs_map[atomical_id] = {
          'expected_outputs': expected_outputs,
          'exponent': highest_exponent
        }
      return potential_atomical_ids_to_output_idxs_map, not non_clean_output_slots, atomical_list
    else:
      return potential_atomical_ids_to_output_idxs_map, not non_clean_output_slots, atomical_list
  
class AtomicalsTransferBlueprintBuilderError(Exception):
    '''Raised when Atomicals Blueprint builder has an error'''

class AtomicalsTransferBlueprintBuilder:
  '''Atomicals transfer blueprint builder for calculating outputs to color'''
  def __init__(self, atomicals_spent_at_inputs, operations_found_at_inputs, tx, get_atomicals_id_mint_info, sort_fifo):
    self.atomicals_spent_at_inputs = atomicals_spent_at_inputs
    self.operations_found_at_inputs = operations_found_at_inputs
    self.tx = tx
    self.get_atomicals_id_mint_info = get_atomicals_id_mint_info
    self.sort_fifo = sort_fifo
    nft_atomicals, ft_atomicals, atomical_ids_spent = self.__build_atomical_type_structs(atomicals_spent_at_inputs)
    self.nft_atomicals = nft_atomicals
    self.ft_atomicals = ft_atomicals
    nft_output_blueprint, ft_output_blueprint = self.__calculate_output_blueprint(self.nft_atomicals, self.ft_atomicals, self.atomicals_spent_at_inputs, self.operations_found_at_inputs, self.sort_fifo)
    self.nft_output_blueprint = nft_output_blueprint
    self.ft_output_blueprint = ft_output_blueprint
    self.are_fts_burned = ft_output_blueprint.get('burned')
    self.atomical_ids_spent = atomical_ids_spent

  @classmethod
  def order_ft_inputs(cls, ft_atomicals, sort_by_fifo):
    atomical_list = []
    # If sorting is by FIFO, then get the mappng of which FTs are at which inputs
    if sort_by_fifo:
      input_idx_map = {}
      for atomical_id, ft_info in ft_atomicals.items():
          for input_index_for_atomical in ft_info['input_indexes']:
            txin_index = input_index_for_atomical['txin_index']
            exponent = input_index_for_atomical['exponent']
            input_idx_map[txin_index] = input_idx_map.get(txin_index) or []
            input_idx_map[txin_index].append({
                'atomical_id': atomical_id,
                'exponent': exponent
            })
      # Now for each input, we assign the atomicals, making sure to ignore the ones we've seen already
      seen_atomical_id_map = {}
      for input_idx, atomicals_array in sorted(input_idx_map.items()):
        for atomical_id_info in sorted(atomicals_array):
          if seen_atomical_id_map.get(atomical_id_info['atomical_id']):       
            continue 
          seen_atomical_id_map[atomical_id] = True
          atomical_list.append({
            'atomical_id': atomical_id,
            'ft_info': ft_atomicals[atomical_id]
          })
    else:
      for atomical_id, ft_info in sorted(ft_atomicals.items()):
        atomical_list.append({
          'atomical_id': atomical_id,
          'ft_info': ft_info
        })
    return atomical_list

  # Maps all the inputs that contain NFTs
  def __build_nft_input_idx_to_atomical_map(self, atomicals_spent_at_inputs):
      input_idx_to_atomical_ids_map = {}
      for txin_index, atomicals_entry_list in atomicals_spent_at_inputs.items():
          for atomicals_entry in atomicals_entry_list:
              atomical_id = atomicals_entry['atomical_id']
              value, = unpack_le_uint64(atomicals_entry['data'][HASHX_LEN + SCRIPTHASH_LEN : HASHX_LEN + SCRIPTHASH_LEN + 8])
              atomical_mint_info = self.get_atomicals_id_mint_info(atomical_id)
              if not atomical_mint_info: 
                  raise AtomicalsTransferBlueprintBuilderError(f'build_atomical_id_info_map {atomical_id.hex()} not found in mint info. IndexError.')
              if atomical_mint_info['type'] != 'NFT':
                  continue
              input_idx_to_atomical_ids_map[txin_index] = input_idx_to_atomical_ids_map.get(txin_index) or {}
              input_idx_to_atomical_ids_map[txin_index][atomical_id] = atomical_mint_info
      return input_idx_to_atomical_ids_map
      
  def __calculate_nft_atomicals_regular(nft_atomicals, tx, atomicals_spent_at_inputs, operations_found_at_inputs, sort_fifo):
    # Use a simplified mapping of NFTs using FIFO to the outputs 
    if sort_fifo:
      next_output_idx = 0
      map_output_idxs_for_atomicals = {}
      # Build a map of input ids to NFTs
      nft_map = self.__build_nft_input_idx_to_atomical_map(atomicals_spent_at_inputs)
      for input_idx, atomicals_ids_map in nft_map.items():
        found_atomical_at_input = False
        for atomical_id, atomical_info in atomicals_ids_map.items():
          assert(len(atomical_info['input_indexes']) == 0)
          found_atomical_at_input = True 
          expected_output_index = next_output_idx
          if expected_output_index >= len(tx.outputs) or is_unspendable_genesis(tx.outputs[expected_output_index].pk_script) or is_unspendable_legacy(tx.outputs[expected_output_index].pk_script):
            expected_output_index = 0
          # Also keep them at the 0'th index if the split command was used
          if is_split_operation(operations_found_at_inputs):
            expected_output_index = 0    
          map_output_idxs_for_atomicals[expected_output_index] = map_output_idxs_for_atomicals.get(expected_output_index) or {'atomicals': {}}
          map_output_idxs_for_atomicals[expected_output_index]['atomicals'][atomical_id] = {
            'info': atomical_info
          }
        if found_atomical_at_input:
          next_output_idx += 1
      return map_output_idxs_for_atomicals
    else:
      output_colored_map = {}
      # Assign NFTs the legacy way with 1:1 inputs to outputs
      for atomical_id, mint_info in nft_atomicals.items():
        assert(len(mint_info['input_indexes']) == 0)
        # The expected output index is equal to the input index normally
        expected_output_index = self.__calculate_nft_output_index_legacy(mint_info['input_indexes'][0], tx, operations_found_at_inputs)
        output_colored_map[atomical_id] = expected_output_index
      return output_colored_map
    
  def __calculate_nft_atomicals_splat(nft_atomicals, tx):
      # Splat takes all of the NFT atomicals across all inputs (including multiple atomicals at the same utxo) 
      # and then separates them into their own distinctive output such that the result of the operation is no two atomicals
      # will share a resulting output. This operation requires that there are at least as many outputs as there are NFT atomicals
      # If there are not enough, then this is considered a noop and those extra NFTs are assigned to output 0
      # If there are enough outputs, then the earliest atomical (sorted lexicographically in ascending order) goes to the 0'th output,
      # then the second atomical goes to the 1'st output, etc until all atomicals are assigned to their own output.
      expected_output_index_incrementing = 0 # Begin assigning splatted atomicals at the 0'th index
      output_colored_map = {}
      for atomical_id, mint_info in sorted(nft_atomicals.items()):
          expected_output_index = expected_output_index_incrementing
          if expected_output_index_incrementing >= len(tx.outputs) or is_unspendable_genesis(tx.outputs[expected_output_index_incrementing].pk_script) or is_unspendable_legacy(tx.outputs[expected_output_index_incrementing].pk_script):
              expected_output_index = 0
          output_colored_map[expected_output_index] = output_colored_map.get(expected_output_index) or {'atomicals': {}}
          output_colored_map[expected_output_index]['atomicals'][atomical_id] = {
            'info': mint_info
          }
          expected_output_index_incrementing += 1 
      return output_colored_map
      
  def __calculate_output_blueprint_nfts(nft_atomicals, atomicals_spent_at_inputs, operations_found_at_inputs, sort_fifo):
      if not nft_atomicals or len(nft_atomicals) == 0:
          return {
            'outputs': {}
          } 
      should_splat_nft_atomicals = is_splat_operation(operations_found_at_inputs)
      if should_splat_nft_atomicals and len(nft_atomicals.keys()) > 0:
          return {
            'outputs': self.__calculate_nft_atomicals_splat(nft_atomicals, tx)  
          }
      else:
          return {
            'outputs': self.__calculate_nft_atomicals_regular(nft_atomicals, tx, atomicals_spent_at_inputs, operations_found_at_inputs, sort_fifo)  
          }
      
  def calculate_output_blueprint_fts(ft_atomicals, atomicals_spent_at_inputs, operations_found_at_inputs, sort_fifo):
      if not ft_atomicals or len(ft_atomicals) == 0:
          return {
              'outputs': {},
              'burned': False
          }
      should_split_ft_atomicals = is_split_operation(operations_found_at_inputs)
      if should_split_ft_atomicals:
          return self.__color_ft_atomicals_split(ft_atomicals, operations_found_at_inputs)
      else:
          return self.__color_ft_atomicals_regular(ft_atomicals, operations_found_at_inputs, sort_fifo)

  def __color_ft_atomicals_split(self, ft_atomicals, operations_found_at_inputs):
      output_colored_map = {
        'outputs': {
        },
        'burned': False
      }
      cleanly_assigned = True
      for atomical_id, atomical_info in sorted(ft_atomicals.items()):
          expected_output_indexes = []
          remaining_value = atomical_info['expected_total_satvalue_output']
          # The FT type has the 'split' (y) method which allows us to selectively split (skip) a certain total number of token units (satoshis)
          # before beginning to color the outputs.
          # Essentially this makes it possible to "split" out multiple FT's located at the same input
          # If the input at index 0 has the split operation, then it will apply for the atomical token generally across all inputs and the first output will be skipped
          total_amount_to_skip = 0
          # Uses the compact form of atomical id as the keys for developer convenience
          compact_atomical_id = location_id_bytes_to_compact(atomical_id)
          total_amount_to_skip_potential = operations_found_at_inputs and operations_found_at_inputs.get('payload').get(compact_atomical_id)
          # Sanity check to ensure it is a non-negative integer
          if isinstance(total_amount_to_skip_potential, int) and total_amount_to_skip_potential >= 0:
              total_amount_to_skip = total_amount_to_skip_potential
          total_skipped_so_far = 0
          for out_idx, txout in enumerate(tx.outputs): 
              # If the first output should be skipped and we have not yet done so, then skip/ignore it
              if total_amount_to_skip > 0 and total_skipped_so_far < total_amount_to_skip:
                  total_skipped_so_far += txout.value 
                  continue 
              # For all remaining outputs attach colors as long as there is adequate remaining_value left to cover the entire output value
              if txout.value <= remaining_value:
                  expected_output_indexes.append(out_idx)
                  remaining_value -= txout.value
                  output_colored_map['outputs'][out_idx] = output_colored_map['outputs'].get(out_idx) or {'atomicals': {}}
                  output_colored_map['outputs'][out_idx]['atomicals'][atomical_id] = {
                    'exponent': atomical_info['max_exponent'],  # Deduce the exponent from the highest exponent 
                    'satvalue': txout.value,                    # Adds expected satvalue for sanity check
                    'info': atomical_info
                  }
                  # We are done assigning all remaining values
                  if remaining_value == 0:
                      break
              # Exit case when we have no more remaining_value to assign or the next output is greater than what we have in remaining_value
              if txout.value > remaining_value or remaining_value < 0:
                  cleanly_assigned = False # Used to indicate that all was cleanly assigned
                  break
          # Used to indicate that all was cleanly assigned
          if remaining_value != 0:
              cleanly_assigned = False
      output_colored_map['burned'] = not cleanly_assigned
      return output_colored_map

  def __color_ft_atomicals_regular(self, ft_atomicals, operations_found_at_inputs, sort_fifo):
      atomical_id_to_expected_outs_map, cleanly_assigned, atomicals_list_result = calculate_outputs_to_color_for_ft_atomical_ids(ft_atomicals, sort_fifo)
      first_atomical_id = None 
      if atomicals_list_result and len(atomicals_list_result):
        first_atomical_id = atomicals_list_result[0]['atomical_id']
      return {
        'burned': not cleanly_assigned,
        'first_atomical_id': first_atomical_id,
        'outputs': atomical_id_to_expected_outs_map
      }

  def color_ft_atomicals_regular(self, ft_atomicals, tx_hash, tx, tx_num, operations_found_at_inputs, atomical_ids_touched, height, live_run):
      return self.color_ft_atomicals_regular_perform(ft_atomicals, tx_hash, tx, tx_num, operations_found_at_inputs, atomical_ids_touched, height, live_run, self.is_dmint_activated(height))

  def __calculate_output_blueprint(nft_atomicals, ft_atomicals, atomicals_spent_at_inputs, operations_found_at_inputs, sort_fifo):
      nft_blueprint = self.calculate_output_blueprint_nfts(nft_atomicals, atomicals_spent_at_inputs, operations_found_at_inputs, sort_fifo)
      ft_blueprint = self.calculate_output_blueprint_fts(ft_atomicals, atomicals_spent_at_inputs, operations_found_at_inputs, sort_fifo)
      return nft_blueprint, ft_blueprint 
      
  # Builds a map and image of all the inputs and their satvalue and tokenvalue (adjusted by exponent)
  # This is the base datastructure used to color FT outputs and determine what exact satvalue will be needed to maintain input token value to outputs
  def __build_atomical_id_info_map(self, map_atomical_ids_to_info, atomicals_entry_list, txin_index):
      atomicals_id_mint_info_map = {}
      # For each input atomical spent at the current input...
      for atomicals_entry in atomicals_entry_list:
          atomical_id = atomicals_entry['atomical_id']
          value, = unpack_le_uint64(atomicals_entry['data'][HASHX_LEN + SCRIPTHASH_LEN : HASHX_LEN + SCRIPTHASH_LEN + 8])
          exponent, = unpack_le_uint16_from(atomicals_entry['data'][HASHX_LEN + SCRIPTHASH_LEN + 8: HASHX_LEN + SCRIPTHASH_LEN + 8 + 2])
          # Perform a cache lookup for the mint information since we do not want to query multiple times for same input atomical_id
          if not atomicals_id_mint_info_map.get(atomical_id):
              atomical_mint_info = self.get_atomicals_id_mint_info(atomical_id)
              if not atomical_mint_info: 
                  raise AtomicalsTransferBlueprintBuilderError(f'build_atomical_id_info_map {atomical_id.hex()} not found in mint info. IndexError.')
              atomicals_id_mint_info_map[atomical_id] = atomical_mint_info
          # The first time we encounter the atomical we build the initialization datastructure
          # it doesn't matter if it's an NFT or FT
          # however note that only FTs will have an exponent >= 0 as NFT will always be exponent = 0
          if map_atomical_ids_to_info.get(atomical_id) == None:
              map_atomical_ids_to_info[atomical_id] = {
                  'atomical_id': atomical_id,
                  'type': atomicals_id_mint_info_map[atomical_id]['type'],
                  'total_satvalue': 0,            # The total satoshi input value accumulated across all inputs
                  'total_tokenvalue': 0,          # The total normalized token input value accumulated across all inputs
                  'input_indexes': [],            # Individual token input indexes and their
                  'max_exponent': 0,              # Track the highest exponent encountered
                  'expected_total_satvalue_output': 0   # Expected output satvalue to disburse according to total_tokenvalue and exponent calculation
              }
          # Accumulate the satvalue
          map_atomical_ids_to_info[atomical_id]['total_satvalue'] += value
          # Calculate the tokenvalue for the current input according to the found exponent
          tokenvalue = get_nominal_token_value(value, exponent)
          # Accumulate the total token value
          map_atomical_ids_to_info[atomical_id]['total_tokenvalue'] += tokenvalue
          # Track the current input index encountered and the details of the input such as satvalue, tokenvalue, exponent, txin index
          map_atomical_ids_to_info[atomical_id]['input_indexes'].append({
              'txin_index': txin_index,
              'satvalue': value,
              'tokenvalue': tokenvalue,
              'exponent': exponent
          })
          # Track the max exponent encountered across all inputs for the same atomical id
          if map_atomical_ids_to_info[atomical_id]['max_exponent'] < exponent:
              map_atomical_ids_to_info[atomical_id]['max_exponent'] = exponent
          # Recalculate the expected satvalue adjusted by the total tokenvalue and highest exponent encountered thus far
          expected_satvalue = get_adjusted_sats_needed_by_exponent(map_atomical_ids_to_info[atomical_id]['total_tokenvalue'], map_atomical_ids_to_info[atomical_id]['max_exponent'])
          # Update the total expected satvalue output reflected
          map_atomical_ids_to_info[atomical_id]['expected_total_satvalue_output'] = expected_satvalue
      return map_atomical_ids_to_info
  
  def __build_atomical_type_structs(self):
      map_atomical_ids_to_info = {}
      for txin_index, atomicals_entry_list in self.atomicals_spent_at_inputs.items():
          # Accumulate the total input value by atomical_id
          # The value will be used below to determine the amount of input we can allocate for FT's
          self.__build_atomical_id_info_map(map_atomical_ids_to_info, atomicals_entry_list, txin_index)
      # Group the atomicals by NFT and FT for easier handling
      # Also store them in a dict 
      nft_atomicals = {}
      ft_atomicals = {}
      for atomical_id, mint_info in map_atomical_ids_to_info.items(): 
          if mint_info['type'] == 'NFT':
              nft_atomicals[atomical_id] = mint_info
          elif mint_info['type'] == 'FT':
              ft_atomicals[atomical_id] = mint_info
          else:
              raise AtomicalsTransferBlueprintBuilderError(f'color_atomicals_outputs: Invalid type. IndexError')
      
      atomicals_ids_spent = []
      for atomical_id, unused in nft_atomicals.items():
        atomicals_ids_spent.append(atomical_id)
      for atomical_id, unused in ft_atomicals.items():
        atomicals_ids_spent.append(atomical_id)

      return nft_atomicals, ft_atomicals, atomicals_ids_spent

  def __validate_ft_transfer_has_no_inflation(atomical_id_to_expected_outs_map, ft_atomicals):
    sanity_check_sums = {}
    for atomical_id, outputs_to_color in atomical_id_to_expected_outs_map.items():
        sanity_check_sums[atomical_id] = 0
        for expected_output_index in outputs_to_color:
            sanity_check_sums[atomical_id] += tx.outputs[expected_output_index].value
    # Sanity check that there can be no inflation
    for atomical_id, ft_info in sorted(ft_atomicals.items()):
        sum_out_value = sanity_check_sums.get(atomical_id)
        input_value = ft_info['value']
        if sum_out_value and sum_out_value > input_value:
            atomical_id_compact = location_id_bytes_to_compact(atomical_id)
            raise AtomicalsTransferBlueprintBuilderError(f'validate_ft_transfer_has_no_inflation: Fatal error the output sum of outputs is greater than input sum for Atomical: atomical_id={atomical_id_compact} input_value={input_value} sum_out_value={sum_out_value} {hash_to_hex_str(tx_hash)} ft_atomicals={ft_atomicals}')
  
  def __calculate_nft_output_index_legacy(input_idx, tx, operations_found_at_inputs):
    expected_output_index = input_idx
    # If it was unspendable output, then just set it to the 0th location
    # ...and never allow an NFT atomical to be burned accidentally by having insufficient number of outputs either
    # The expected output index will become the 0'th index if the 'x' extract operation was specified or there are insufficient outputs
    if expected_output_index >= len(tx.outputs) or is_unspendable_genesis(tx.outputs[expected_output_index].pk_script) or is_unspendable_legacy(tx.outputs[expected_output_index].pk_script):
        expected_output_index = 0
    # If this was the 'split' (y) command, then also move them to the 0th output
    if is_split_operation(operations_found_at_inputs):
      expected_output_index = 0      
    return expected_output_index


  # Assign the ft quantity basic from the start_out_idx to the end until exhausted
  # Returns the sequence of output indexes that matches until the final one that matched
  # Also returns whether it fit cleanly in (ie: exact with no left overs or under)
  @classmethod
  def assign_expected_outputs_basic(cls, atomical_id, ft_value, tx, start_out_idx):
      expected_output_indexes = []
      remaining_value = ft_value
      idx_count = 0
      if start_out_idx >= len(tx.outputs):
          return False, expected_output_indexes
      for out_idx, txout in enumerate(tx.outputs): 
          # Only consider outputs from the starting index
          if idx_count < start_out_idx:
              idx_count += 1
              continue
          # For all remaining outputs attach colors as long as there is adequate remaining_value left to cover the entire output value
          if is_unspendable_genesis(txout.pk_script) or is_unspendable_legacy(txout.pk_script):
              idx_count += 1
              continue
          if txout.value <= remaining_value:
              expected_output_indexes.append(out_idx)
              remaining_value -= txout.value
              if remaining_value == 0:
                  # The token input was fully exhausted cleanly into the outputs
                  return True, expected_output_indexes
          # Exit case output is greater than what we have in remaining_value
          else:
              # There was still some token units left, but the next output was greater than the amount. Therefore we burned the remainder tokens.
              return False, expected_output_indexes
          idx_count += 1
      # There was still some token units left, but there were no more outputs to take the quantity. Tokens were burned.
      return False, expected_output_indexes 

  def get_nft_output_blueprint():
    return nft_output_blueprint
  
  def get_ft_output_blueprint():
    return ft_output_blueprint

  def get_are_fts_burned()
    return self.are_fts_burned

  def get_atomical_ids_spent():
    return self.atomical_ids_spent
