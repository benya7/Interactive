// ./app/settings/chains/page.tsx
'use client';

import React, { useState, useEffect, useMemo, useCallback, useContext, memo } from 'react';
import { useRouter, usePathname, useSearchParams } from 'next/navigation';
import ReactFlow, {
  Controls,
  Background,
  applyNodeChanges,
  applyEdgeChanges,
  Node,
  Edge,
  NodeChange,
  EdgeChange,
  Connection,
  addEdge,
  Position,
  MarkerType,
  NodeProps,
  Handle,
  useReactFlow,
  ReactFlowProvider,
  // ReactFlowInstance // Not explicitly needed with useReactFlow hook
} from 'reactflow';
import 'reactflow/dist/style.css';
import { Check, Download, Pencil, Plus, Save, Trash2, Upload, X, ArrowDown, ArrowUp, Loader2 } from 'lucide-react';
import useSWR, { mutate as globalMutate } from 'swr';

import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogDescription,
  DialogTrigger, // Added for step delete confirmation
  DialogClose, // Added for step delete confirmation
} from '@/components/ui/dialog';
import { Switch } from '@/components/ui/switch';
import PromptSelector from '@/components/layout/PromptSelector'; // Assuming this path is correct

import { SidebarPage } from '@/components/layout/SidebarPage';
import { useInteractiveConfig } from '@/components/interactive/InteractiveConfigContext';
import { useAgent } from '@/components/interactive/useAgent';
// Assuming your useChain hook correctly fetches the updated ChainStepType
// with `target_name` and `prompt` (args only) from GraphQL
import { useChain, useChains, ChainStep as ChainStepType } from '@/components/interactive/useChain';
import { toast } from '@/components/layout/toast';
import { cn } from '@/lib/utils';

// --- Selectors (No changes needed here, assuming internal interaction fixes are done) ---

function CommandSelector({
  agentName,
  value,
  onChange,
}: {
  agentName: string;
  value?: string | null;
  onChange?: (value: string | null) => void;
}): React.JSX.Element {
  const { data: agentData, error, isLoading } = useAgent(false, agentName);

  if (isLoading) return <div className='text-xs text-muted-foreground h-8 flex items-center'>Loading...</div>;
  if (error) return <div className='text-xs text-destructive h-8 flex items-center'>Load Error</div>;

  const commandsObject = agentData?.commands ?? {};
  const commandKeys = commandsObject && typeof commandsObject === 'object' ? Object.keys(commandsObject) : [];

  const stopPropagation = (e: React.MouseEvent | React.TouchEvent) => {
    e.stopPropagation();
  };

  return (
    <div className='w-full'>
      <Select
        disabled={!commandKeys.length}
        value={value || undefined}
        onValueChange={(value) => onChange?.(value === '/' ? null : value)}
      >
        <SelectTrigger className='w-full h-8 text-xs nopan' onMouseDown={stopPropagation} onTouchStart={stopPropagation}>
          <SelectValue placeholder='Select Command' />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value='/'>- None -</SelectItem>
          {commandKeys.map(
            (command) =>
              command && (
                <SelectItem key={command} value={command}>
                  {command}
                </SelectItem>
              ),
          )}
        </SelectContent>
      </Select>
    </div>
  );
}

function ChainSelector({
  value,
  onChange,
}: {
  value?: string | null;
  onChange?: (value: string | null) => void;
}): React.JSX.Element {
  const { data: chainData, error, isLoading } = useChains();

  if (isLoading) return <div className='text-xs text-muted-foreground h-8 flex items-center'>Loading...</div>;
  if (error) return <div className='text-xs text-destructive h-8 flex items-center'>Load Error</div>;

  const stopPropagation = (e: React.MouseEvent | React.TouchEvent) => {
    e.stopPropagation();
  };

  return (
    <div className='w-full'>
      <Select
        disabled={!chainData || chainData.length === 0}
        value={value || undefined}
        onValueChange={(value) => onChange?.(value === '/' ? null : value)}
      >
        <SelectTrigger className='w-full h-8 text-xs nopan' onMouseDown={stopPropagation} onTouchStart={stopPropagation}>
          <SelectValue placeholder='Select Chain' />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value='/'>- None -</SelectItem>
          {chainData?.map((chain) => (
            <SelectItem key={chain.id} value={chain.chainName}>
              {chain.chainName}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}

// --- ReactFlow Custom Node ---

const ignoreArgs = [
  // Keep agent_name and conversation_name as they might be useful for context within commands/prompts sometimes
  'command_list',
  'context', // Usually injected by the backend based on other args
  'COMMANDS',
  'date',
  'working_directory',
  'helper_agent_name',
  // 'conversation_history', // Might be needed in some prompts
  'persona',
  'import_files', // Usually handled at a higher level
  'output_url',
];

// --- Updated ChainStepType based on GraphQL changes ---
// Note: This should ideally match the type returned by your useChain hook
// If useChain already returns this structure, you don't need to redefine it here.
interface UpdatedChainStepType {
  step: number;
  agentName: string;
  prompt_type: string;
  target_name: string; // Holds the prompt/command/chain name
  prompt: Record<string, any>; // Holds ONLY the arguments
}

// Assuming NodeProps data is now of type UpdatedChainStepType
const ChainStepNode = memo(
  ({
    data,
    isConnectable,
  }: NodeProps<{
    // Update the expected type here
    stepData: UpdatedChainStepType;
    chainName: string;
    mutateChain: () => void;
    mutateChains: () => void;
    isLastStep: boolean;
    moveStep: (stepNumber: number, direction: 'up' | 'down') => Promise<void>;
  }>) => {
    const { stepData, chainName, mutateChain, mutateChains, isLastStep, moveStep } = data;
    const context = useInteractiveConfig();
    const [agentName, setAgentName] = useState(stepData.agentName);

    // --- FIXED: State Initialization based on new GraphQL structure ---
    const initialStepType = stepData.prompt_type || 'Prompt'; // Use prompt_type directly
    const initialTargetName = stepData.target_name || ''; // Use target_name directly
    const [stepType, setStepType] = useState(initialStepType);
    const [targetName, setTargetName] = useState(initialTargetName);

    // --- Args state initialization should now work correctly ---
    // stepData.prompt (from GraphQL) *should* only contain arguments now
    const [args, setArgs] = useState<Record<string, string | number | boolean>>(() => {
      const initialArgs: Record<string, string | number | boolean> = {};
      // Defensive check: Ensure stepData.prompt is a valid object
      if (stepData.prompt && typeof stepData.prompt === 'object' && !Array.isArray(stepData.prompt)) {
        for (const key in stepData.prompt) {
          // Ensure the key isn't accidentally one of the name keys or ignored args
          if (
            !ignoreArgs.includes(key) &&
            key !== 'prompt_name' &&
            key !== 'prompt_category' &&
            key !== 'command_name' &&
            key !== 'chain_name' &&
            key !== 'chain' // Just in case 'chain' was used before
          ) {
            const value = (stepData.prompt as any)[key]; // Type assertion might be needed
            if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
              initialArgs[key] = value;
            } else if (value === null || value === undefined) {
              initialArgs[key] = ''; // Handle null/undefined as empty string
            } else {
              console.warn(`Unexpected type for argument '${key}': ${typeof value}. Setting to empty string.`);
              initialArgs[key] = ''; // Default for other types
            }
          }
        }
      } else if (stepData.prompt !== null && stepData.prompt !== undefined) {
        console.warn(`stepData.prompt is not a valid object for step ${stepData.step}:`, stepData.prompt);
      }
      return initialArgs;
    });
    // --- End Args State Initialization ---

    const [availableArgs, setAvailableArgs] = useState<string[]>([]);
    const [modified, setModified] = useState(false);
    const [isLoadingArgs, setIsLoadingArgs] = useState(false);
    const [isDeleteConfirmOpen, setIsDeleteConfirmOpen] = useState(false);

    // Fetch available agents using SWR
    const { data: agentsData, isLoading: isAgentsLoading } = useSWR('/agents', () => context.agixt.getAgents(), {
      fallbackData: [],
    });

    // Memoize sorted agent names
    const sortedAgents = useMemo(
      () =>
        agentsData
          ?.map((agent: any) => agent.name as string)
          .sort((a: string, b: string) => a.toLowerCase().localeCompare(b.toLowerCase())) || [],
      [agentsData],
    );

    // Callback to fetch arguments based on step type and target name
    const fetchArgs = useCallback(async () => {
      if (!targetName || !stepType) {
        setAvailableArgs([]);
        setArgs({}); // Clear args when target is empty
        return;
      }
      setIsLoadingArgs(true);
      let fetchedArgNames: string[] = [];
      let result: any;
      try {
        // Fetch arguments based on the selected step type
        if (stepType === 'Prompt') {
          result = await context.agixt.getPromptArgs(targetName, 'Default');
          fetchedArgNames = Array.isArray(result?.prompt_args) ? result.prompt_args.map(String) : [];
        } else if (stepType === 'Chain') {
          result = await context.agixt.getChainArgs(targetName);
          fetchedArgNames = Array.isArray(result?.chain_args) ? result.chain_args.map(String) : [];
        } else if (stepType === 'Command') {
          result = await context.agixt.getCommandArgs(targetName);
          // Check if result is the expected args object
          if (typeof result?.command_args === 'object' && result.command_args !== null) {
            fetchedArgNames = Object.keys(result.command_args);
          } else {
            console.warn(`Unexpected command args result for ${targetName}:`, result);
          }
        }
      } catch (error: any) {
        console.error(`Error fetching args for ${stepType} ${targetName}:`, error);
        toast({
          title: 'Error Fetching Args',
          description: `Could not load arguments for ${stepType} '${targetName}'. ${error.message || ''}`,
          variant: 'destructive',
        });
      } finally {
        // Filter out ignored arguments
        const filteredArgNames = fetchedArgNames.filter((arg) => !ignoreArgs.includes(arg));
        setAvailableArgs(filteredArgNames);

        // Update args state, preserving existing values if keys match, otherwise initializing
        setArgs((prevArgs) => {
          const newArgs = filteredArgNames.reduce(
            (acc, key) => {
              // Preserve existing value if the key is still available, otherwise initialize
              acc[key] = prevArgs.hasOwnProperty(key) ? prevArgs[key] : '';
              return acc;
            },
            {} as Record<string, string | number | boolean>,
          );
          return newArgs;
        });
        setIsLoadingArgs(false);
      }
    }, [stepType, targetName, context.agixt]); // Dependencies for fetching args

    // Fetch arguments when step type or target name changes
    useEffect(() => {
      fetchArgs();
    }, [fetchArgs]);

    // Handler to save the step changes
    const handleSave = async (): Promise<void> => {
      if (!chainName || typeof chainName !== 'string' || chainName.trim() === '') {
        toast({
          title: 'Error Saving Step',
          description: 'Chain name is missing or invalid. Cannot save.',
          variant: 'destructive',
        });
        console.error('handleSave called without a valid chainName. Current value:', chainName);
        return;
      }

      // --- FIXED: Reconstruct the 'prompt' object expected by the backend's updateStep ---
      const promptPayload: Record<string, any> = {};
      let validationError = false;
      let nameKey = ''; // Key for the name (e.g., 'prompt_name')

      if (stepType === 'Prompt') {
        if (!targetName) {
          toast({ title: 'Error', description: 'Prompt Name is required.', variant: 'destructive' });
          validationError = true;
        }
        nameKey = 'prompt_name';
        promptPayload[nameKey] = targetName;
        promptPayload.prompt_category = 'Default'; // Assuming Default
      } else if (stepType === 'Command') {
        if (!targetName) {
          toast({ title: 'Error', description: 'Command Name is required.', variant: 'destructive' });
          validationError = true;
        }
        nameKey = 'command_name';
        promptPayload[nameKey] = targetName;
      } else if (stepType === 'Chain') {
        if (!targetName) {
          toast({ title: 'Error', description: 'Chain Name is required.', variant: 'destructive' });
          validationError = true;
        }
        nameKey = 'chain_name'; // Use 'chain_name' as expected by backend
        promptPayload[nameKey] = targetName;
      } else {
        toast({ title: 'Error', description: 'Invalid step type selected.', variant: 'destructive' });
        validationError = true;
      }

      if (validationError) return;

      // Add the current arguments from the state to the payload
      availableArgs.forEach((key) => {
        if (args.hasOwnProperty(key)) {
          promptPayload[key] = args[key];
        }
      });
      // --- End Reconstruct Prompt Payload ---

      try {
        // Call the SDK function to update the step with the reconstructed payload
        await context.agixt.updateStep(chainName, stepData.step, agentName, stepType, promptPayload);
        await mutateChain(); // Re-fetch the chain data to update the UI
        setModified(false); // Reset modification state
        toast({ title: 'Step Saved', description: `Step ${stepData.step} updated.` });
      } catch (err: any) {
        console.error('Failed to save step:', err);
        toast({ title: 'Error Saving Step', description: err.message || 'API error.', variant: 'destructive' });
      }
    };

    // Handler for confirming step deletion
    const handleDeleteConfirm = async (): Promise<void> => {
      try {
        await context.agixt.deleteStep(chainName, stepData.step);
        await mutateChain(); // Update the current chain view
        await mutateChains(); // Update the list of all chains (if needed)
        toast({ title: 'Step Deleted', description: `Step ${stepData.step} removed.` });
        setIsDeleteConfirmOpen(false); // Close the confirmation dialog
      } catch (err: any) {
        console.error('Failed to delete step:', err);
        toast({ title: 'Error Deleting Step', description: err.message || 'API error.', variant: 'destructive' });
        setIsDeleteConfirmOpen(false); // Close dialog even on error
      }
    };

    // Memoize components for selecting Prompt/Command/Chain
    const stepTypeComponents = useMemo(
      () => ({
        Prompt: (
          <div>
            <Label htmlFor={`prompt-name-${stepData.step}`} className='text-xs'>
              Prompt Name
            </Label>
            {/* Use targetName state */}
            <PromptSelector
              value={targetName}
              onChange={(val) => {
                if (val !== targetName) {
                  setTargetName(val || '');
                  setModified(true);
                  setArgs({});
                  setAvailableArgs([]);
                }
              }}
            />
          </div>
        ),
        Command: (
          <div>
            <Label htmlFor={`command-name-${stepData.step}`} className='text-xs'>
              Command Name
            </Label>
            {/* Use targetName state */}
            <CommandSelector
              agentName={agentName}
              value={targetName}
              onChange={(val) => {
                if (val !== targetName) {
                  setTargetName(val || '');
                  setModified(true);
                  setArgs({});
                  setAvailableArgs([]);
                }
              }}
            />
          </div>
        ),
        Chain: (
          <div>
            <Label htmlFor={`chain-name-${stepData.step}`} className='text-xs'>
              Chain Name
            </Label>
            {/* Use targetName state */}
            <ChainSelector
              value={targetName}
              onChange={(val) => {
                if (val !== targetName) {
                  setTargetName(val || '');
                  setModified(true);
                  setArgs({});
                  setAvailableArgs([]);
                }
              }}
            />
          </div>
        ),
      }),
      [agentName, targetName, stepData.step],
    );

    // Helper to stop event propagation
    const stopPropagation = (e: React.MouseEvent | React.TouchEvent) => {
      e.stopPropagation();
    };

    // --- JSX Rendering (Mostly unchanged, relies on updated state) ---
    return (
      <Card className='w-80 shadow-md nowheel nopan'>
        <Handle type='target' position={Position.Left} style={{ background: '#555' }} isConnectable={isConnectable} />
        <CardHeader className='p-3 bg-muted/50 cursor-default'>
          <CardTitle className='text-sm font-semibold flex justify-between items-center'>
            <span>Step {stepData.step}</span>
            <div className='flex items-center space-x-1' onMouseDown={stopPropagation} onTouchStart={stopPropagation}>
              <TooltipProvider delayDuration={100}>
                {/* Move Buttons */}
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button
                      variant='ghost'
                      size='icon'
                      className='h-6 w-6'
                      onClick={() => moveStep(stepData.step, 'up')}
                      disabled={stepData.step === 1}
                    >
                      <ArrowUp className='h-3 w-3' />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>Move Up</TooltipContent>
                </Tooltip>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button
                      variant='ghost'
                      size='icon'
                      className='h-6 w-6'
                      onClick={() => moveStep(stepData.step, 'down')}
                      disabled={isLastStep}
                    >
                      <ArrowDown className='h-3 w-3' />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>Move Down</TooltipContent>
                </Tooltip>
                {/* Save Button */}
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button variant='ghost' size='icon' className='h-6 w-6' onClick={handleSave} disabled={!modified}>
                      <Save className={cn('h-3 w-3', !modified && 'text-muted-foreground/50')} />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>{modified ? 'Save Changes' : 'No Changes'}</TooltipContent>
                </Tooltip>
                {/* Delete Button */}
                <Dialog open={isDeleteConfirmOpen} onOpenChange={setIsDeleteConfirmOpen}>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <DialogTrigger asChild>
                        <Button variant='ghost' size='icon' className='h-6 w-6 text-destructive'>
                          <X className='h-4 w-4' />
                        </Button>
                      </DialogTrigger>
                    </TooltipTrigger>
                    <TooltipContent>Delete Step</TooltipContent>
                  </Tooltip>
                  <DialogContent>
                    <DialogHeader>
                      <DialogTitle>Confirm Deletion</DialogTitle>
                      <DialogDescription>Are you sure you want to delete Step {stepData.step}?</DialogDescription>
                    </DialogHeader>
                    <DialogFooter>
                      <DialogClose asChild>
                        <Button variant='outline'>Cancel</Button>
                      </DialogClose>
                      <Button variant='destructive' onClick={handleDeleteConfirm}>
                        Delete
                      </Button>
                    </DialogFooter>
                  </DialogContent>
                </Dialog>
              </TooltipProvider>
            </div>
          </CardTitle>
        </CardHeader>
        <CardContent className='p-3 space-y-2 text-xs max-h-96 overflow-y-auto relative z-10'>
          {/* Agent Selector */}
          <div onMouseDown={stopPropagation} onTouchStart={stopPropagation}>
            <Label htmlFor={`agent-name-${stepData.step}`} className='text-xs'>
              Agent
            </Label>
            <Select
              value={agentName}
              onValueChange={(value) => {
                setAgentName(value);
                setModified(true);
              }}
              disabled={isAgentsLoading || !sortedAgents.length}
            >
              <SelectTrigger id={`agent-name-${stepData.step}`} className='h-8 text-xs nopan'>
                <SelectValue placeholder={isAgentsLoading ? 'Loading...' : 'Select Agent'} />
              </SelectTrigger>
              <SelectContent>
                {sortedAgents.map((agent) => (
                  <SelectItem key={agent} value={agent}>
                    {agent}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Step Type Selector */}
          <div onMouseDown={stopPropagation} onTouchStart={stopPropagation}>
            <Label htmlFor={`step-type-${stepData.step}`} className='text-xs'>
              Type
            </Label>
            <Select
              value={stepType}
              onValueChange={(value) => {
                if (value !== stepType) {
                  setTargetName('');
                  setArgs({});
                  setAvailableArgs([]);
                  setStepType(value);
                  setModified(true);
                }
              }}
            >
              <SelectTrigger id={`step-type-${stepData.step}`} className='h-8 text-xs nopan'>
                <SelectValue placeholder='Select Type' />
              </SelectTrigger>
              <SelectContent>
                {Object.keys(stepTypeComponents).map((type) => (
                  <SelectItem key={type} value={type}>
                    {type}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Dynamically render Prompt/Command/Chain selector */}
          {stepType && stepTypeComponents[stepType as keyof typeof stepTypeComponents]}

          {/* Arguments Section */}
          {isLoadingArgs && (
            <div className='flex items-center justify-center py-2'>
              <Loader2 className='h-4 w-4 animate-spin text-muted-foreground' />
            </div>
          )}
          {!isLoadingArgs && availableArgs.length > 0 && (
            <div className='mt-2 space-y-2 border-t pt-2'>
              <Label className='text-xs font-medium'>Arguments</Label>
              {availableArgs.map((name) => {
                const label = name.replace(/_/g, ' ').replace(/(?:^|\s)\S/g, (char) => char.toUpperCase());
                const argId = `arg-${stepData.step}-${name}`;
                const currentValue = args.hasOwnProperty(name) ? args[name] : '';
                const isBoolean =
                  name.toLowerCase().includes('enable') ||
                  name.toLowerCase().startsWith('is_') ||
                  typeof currentValue === 'boolean';
                const isNumber =
                  name.toLowerCase().includes('count') ||
                  name.toLowerCase().includes('number') ||
                  name.toLowerCase().includes('depth') ||
                  name.toLowerCase().includes('limit') ||
                  typeof currentValue === 'number';

                if (isBoolean) {
                  const checkedValue =
                    typeof currentValue === 'boolean' ? currentValue : String(currentValue).toLowerCase() === 'true';
                  return (
                    <div
                      key={name}
                      className='flex items-center space-x-2'
                      onMouseDown={stopPropagation}
                      onTouchStart={stopPropagation}
                    >
                      <Switch
                        id={argId}
                        checked={checkedValue}
                        onCheckedChange={(checked) => {
                          setArgs((prev) => ({ ...prev, [name]: checked }));
                          setModified(true);
                        }}
                        className='nopan'
                      />
                      <Label htmlFor={argId} className='text-xs cursor-pointer'>
                        {label}
                      </Label>
                    </div>
                  );
                }
                return (
                  <div key={name} onMouseDown={stopPropagation} onTouchStart={stopPropagation}>
                    <Label htmlFor={argId} className='text-xs'>
                      {label}
                    </Label>
                    <Input
                      id={argId}
                      value={String(currentValue ?? '')}
                      type={isNumber ? 'number' : 'text'}
                      onChange={(e) => {
                        const newValue = isNumber ? Number(e.target.value) || 0 : e.target.value;
                        setArgs((prev) => ({ ...prev, [name]: newValue }));
                        setModified(true);
                      }}
                      className='w-full h-8 text-xs nopan'
                      placeholder={`Enter ${label}`}
                    />
                  </div>
                );
              })}
            </div>
          )}
          {!isLoadingArgs && stepType && targetName && availableArgs.length === 0 && (
            <p className='text-xs text-muted-foreground mt-2 italic'>No arguments required.</p>
          )}
        </CardContent>
        <Handle type='source' position={Position.Right} style={{ background: '#555' }} isConnectable={isConnectable} />
      </Card>
    );
  },
);
ChainStepNode.displayName = 'ChainStepNode'; // Set display name for debugging

// --- Main Flow Component (No changes needed here unless useChain hook needs updating) ---
const NODE_WIDTH = 320; // Width of each node card
const HORIZONTAL_SPACING = 60; // Horizontal space between nodes
const VERTICAL_POSITION = 50; // Vertical position of the nodes

function ChainFlow() {
  const [nodes, setNodes] = useState<Node[]>([]);
  const [edges, setEdges] = useState<Edge[]>([]);
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [newChainName, setNewChainName] = useState('');
  const [renaming, setRenaming] = useState(false);
  const [currentChainName, setCurrentChainName] = useState<string | null>(null);
  const [newName, setNewName] = useState('');

  const reactFlowInstance = useReactFlow<any, any>();
  const context = useInteractiveConfig();
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const selectedChainName = searchParams.get('chain');

  const { data: chainsData, mutate: mutateChains } = useChains();
  // Assume useChain hook now fetches the correct UpdatedChainStepType[]
  const {
    data: chainData,
    mutate: mutateChain,
    error: chainError,
    isLoading: isChainLoading,
  } = useChain(selectedChainName ?? undefined);
  const { data: agentData } = useAgent(false);

  const onNodesChange = useCallback(
    (changes: NodeChange[]) => setNodes((nds) => applyNodeChanges(changes, nds)),
    [setNodes],
  );
  const onEdgesChange = useCallback(
    (changes: EdgeChange[]) => setEdges((eds) => applyEdgeChanges(changes, eds)),
    [setEdges],
  );

  const moveStep = useCallback(
    async (stepNumber: number, direction: 'up' | 'down') => {
      if (!currentChainName || !chainData) return;
      const newStepNumber = direction === 'up' ? stepNumber - 1 : stepNumber + 1;
      if (newStepNumber < 1 || newStepNumber > chainData.steps.length) return;
      try {
        await context.agixt.moveStep(currentChainName, stepNumber, newStepNumber);
        await mutateChain();
        toast({ title: 'Step Moved', description: `Step ${stepNumber} moved ${direction}.` });
      } catch (err: any) {
        console.error('Error moving step:', err);
        toast({ title: 'Error Moving Step', description: err.message || 'API error.', variant: 'destructive' });
      }
    },
    [currentChainName, chainData, context.agixt, mutateChain],
  );

  useEffect(() => {
    if (chainData?.steps) {
      const numSteps = chainData.steps.length;
      // Expect chainData.steps to have the updated structure (target_name, prompt: args)
      const newNodes: Node[] = chainData.steps.map((step, index) => ({
        id: `step-${step.step}`,
        type: 'chainStep',
        position: { x: index * (NODE_WIDTH + HORIZONTAL_SPACING), y: VERTICAL_POSITION },
        data: {
          stepData: step, // Pass the potentially updated step structure
          chainName: chainData.chainName,
          mutateChain,
          mutateChains,
          isLastStep: index === numSteps - 1,
          moveStep,
        },
        draggable: false,
        connectable: false,
        selectable: false,
        style: { width: NODE_WIDTH },
      }));

      const newEdges: Edge[] = chainData.steps.slice(0, -1).map((step) => ({
        id: `e${step.step}-${step.step + 1}`,
        source: `step-${step.step}`,
        target: `step-${step.step + 1}`,
        markerEnd: { type: MarkerType.ArrowClosed, width: 20, height: 20 },
        type: 'smoothstep',
        style: { strokeWidth: 2 },
      }));

      setNodes(newNodes);
      setEdges(newEdges);
      setTimeout(() => reactFlowInstance?.fitView({ padding: 0.2, duration: 300 }), 50);
    } else {
      setNodes([]);
      setEdges([]);
    }
  }, [chainData, mutateChain, mutateChains, reactFlowInstance, moveStep]);

  useEffect(() => {
    setCurrentChainName(selectedChainName);
    if (renaming && selectedChainName) {
      setNewName(selectedChainName);
    } else if (!selectedChainName) {
      setRenaming(false);
      setNewName('');
    }
  }, [selectedChainName, renaming]);

  const handleSelectChain = (value: string | null) => {
    const current = new URLSearchParams(Array.from(searchParams.entries()));
    if (value && value !== '/') {
      current.set('chain', value);
    } else {
      current.delete('chain');
    }
    router.replace(`${pathname}?${current.toString()}`, { scroll: false });
    setNodes([]);
    setEdges([]);
  };

  const handleNewChain = async () => {
    if (!newChainName) {
      toast({ title: 'Error', description: 'Chain name is required.', variant: 'destructive' });
      return;
    }
    try {
      await context.agixt.addChain(newChainName);
      await mutateChains();
      router.push(`/settings/chains?chain=${encodeURIComponent(newChainName)}`);
      toast({ title: 'Chain Created', description: `Successfully created "${newChainName}".` });
      setShowCreateDialog(false);
      setNewChainName('');
    } catch (err: any) {
      console.error('Error creating chain:', err);
      toast({ title: 'Error Creating Chain', description: err.message || 'API error.', variant: 'destructive' });
    }
  };

  const handleChainImport = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const finalChainName = newChainName || file.name.replace(/\.json$/i, '');
    if (!finalChainName) {
      toast({ title: 'Error', description: 'Chain name is required for import.', variant: 'destructive' });
      return;
    }

    try {
      const fileContent = await file.text();
      const stepsData = JSON.parse(fileContent); // Parse as raw data
      // Let the backend handle the import structure validation
      await context.agixt.importChain(finalChainName, stepsData);
      await mutateChains();
      router.push(`/settings/chains?chain=${encodeURIComponent(finalChainName)}`);
      toast({ title: 'Chain Imported', description: `Successfully imported "${finalChainName}".` });
      setShowCreateDialog(false);
      setNewChainName('');
    } catch (err: any) {
      console.error('Error importing chain:', err);
      toast({ title: 'Error Importing Chain', description: err.message || 'API error.', variant: 'destructive' });
    }
  };

  const handleDeleteChain = async () => {
    if (!currentChainName) return;
    const confirmed = window.confirm(
      `Are you sure you want to delete the chain "${currentChainName}"? This cannot be undone.`,
    );
    if (!confirmed) return;

    try {
      await context.agixt.deleteChain(currentChainName);
      await mutateChains();
      const firstChainName = chainsData?.filter((c) => c.chainName !== currentChainName)[0]?.chainName;
      handleSelectChain(firstChainName || null);
      toast({ title: 'Chain Deleted', description: `Successfully deleted "${currentChainName}".` });
    } catch (err: any) {
      console.error('Error deleting chain:', err);
      toast({ title: 'Error Deleting Chain', description: err.message || 'API error.', variant: 'destructive' });
    }
  };

  const handleRenameChain = async () => {
    if (!newName || !currentChainName) {
      setRenaming(false);
      return;
    }
    if (newName === currentChainName) {
      setRenaming(false);
      toast({ title: 'Info', description: 'Name is the same, rename cancelled.' });
      return;
    }
    try {
      await context.agixt.renameChain(currentChainName, newName);
      setRenaming(false);
      await mutateChains();
      const current = new URLSearchParams(Array.from(searchParams.entries()));
      current.set('chain', newName);
      router.replace(`${pathname}?${current.toString()}`, { scroll: false });
      toast({ title: 'Chain Renamed', description: `Renamed to "${newName}".` });
    } catch (err: any) {
      console.error('Error renaming chain:', err);
      toast({ title: 'Error Renaming Chain', description: err.message || 'API error.', variant: 'destructive' });
      setRenaming(false);
    }
  };

  const handleExportChain = async () => {
    if (!currentChainName || !chainData?.steps) {
      toast({ title: 'Error', description: 'No chain selected or chain data is empty.', variant: 'destructive' });
      return;
    }
    try {
      // Fetch the raw chain data again for export to ensure it includes args correctly
      const rawChainData = await context.agixt.getChain(currentChainName);
      if (!rawChainData) throw new Error('Failed to fetch chain data for export');

      const element = document.createElement('a');
      // Export the 'steps' part of the raw data
      const file = new Blob([JSON.stringify(rawChainData.steps, null, 2)], { type: 'application/json' });
      element.href = URL.createObjectURL(file);
      element.download = `${currentChainName}.json`;
      document.body.appendChild(element);
      element.click();
      document.body.removeChild(element);
      toast({ title: 'Chain Exported', description: `Successfully exported "${currentChainName}".` });
    } catch (err: any) {
      console.error('Error exporting chain:', err);
      toast({ title: 'Error Exporting Chain', description: err.message || 'API error.', variant: 'destructive' });
    }
  };

  const handleAddStep = async () => {
    if (!chainData || !currentChainName) {
      toast({ title: 'Error', description: 'No chain selected.', variant: 'destructive' });
      return;
    }
    const lastStep = chainData.steps.length > 0 ? chainData.steps[chainData.steps.length - 1] : null;
    const newStepNumber = chainData.steps.length + 1;
    const defaultAgent = agentData?.agent?.name ?? 'AGiXT';

    // Construct the default prompt object correctly for the backend
    const defaultPromptPayload: Record<string, any> = {
      prompt_name: '', // Start with empty prompt name
      prompt_category: 'Default',
    };

    try {
      await context.agixt.addStep(
        currentChainName,
        newStepNumber,
        lastStep ? lastStep.agentName : defaultAgent,
        'Prompt', // Default type
        defaultPromptPayload, // Send the structured payload
      );
      await mutateChain();
      toast({ title: 'Step Added', description: `Step ${newStepNumber} added to chain.` });
      setTimeout(() => reactFlowInstance?.fitView({ padding: 0.2, duration: 300 }), 100);
    } catch (err: any) {
      console.error('Error adding step:', err);
      toast({ title: 'Error Adding Step', description: err.message || 'API error.', variant: 'destructive' });
    }
  };

  const nodeTypes = useMemo(() => ({ chainStep: ChainStepNode }), []);

  // --- JSX Rendering (Mostly unchanged) ---
  return (
    <>
      <Card>
        <CardContent className='p-4 space-y-4'>
          <Label>Select or Manage Chain</Label>
          <TooltipProvider delayDuration={100}>
            <div className='flex items-center space-x-2'>
              <div className='flex-1'>
                {renaming ? (
                  <Input
                    value={newName}
                    onChange={(e) => setNewName(e.target.value)}
                    placeholder='Enter new chain name'
                    className='h-9'
                  />
                ) : (
                  <Select value={currentChainName || ''} onValueChange={handleSelectChain} disabled={!chainsData}>
                    <SelectTrigger className='w-full h-9'>
                      <SelectValue placeholder={!chainsData ? 'Loading Chains...' : 'Select a Chain'} />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value='/'>- Select -</SelectItem>
                      {chainsData?.map((chain) => (
                        <SelectItem key={chain.id} value={chain.chainName}>
                          {chain.chainName}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                )}
              </div>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant='ghost'
                    size='icon'
                    onClick={() => setShowCreateDialog(true)}
                    disabled={renaming}
                    className='h-9 w-9'
                  >
                    <Plus className='h-4 w-4' />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Create or Import Chain</TooltipContent>
              </Tooltip>
              {currentChainName && (
                <>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Button
                        variant='ghost'
                        size='icon'
                        onClick={handleExportChain}
                        disabled={renaming || !chainData}
                        className='h-9 w-9'
                      >
                        <Download className='h-4 w-4' />
                      </Button>
                    </TooltipTrigger>
                    <TooltipContent>Export Chain Steps (JSON)</TooltipContent>
                  </Tooltip>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Button
                        variant='ghost'
                        size='icon'
                        onClick={renaming ? handleRenameChain : () => setRenaming(true)}
                        disabled={!currentChainName}
                        className='h-9 w-9'
                      >
                        {renaming ? <Check className='h-4 w-4' /> : <Pencil className='h-4 w-4' />}
                      </Button>
                    </TooltipTrigger>
                    <TooltipContent>{renaming ? 'Save New Name' : 'Rename Chain'}</TooltipContent>
                  </Tooltip>
                  {renaming && (
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button
                          variant='ghost'
                          size='icon'
                          onClick={() => {
                            setRenaming(false);
                            setNewName(currentChainName || '');
                          }}
                          className='h-9 w-9 text-muted-foreground'
                        >
                          <X className='h-4 w-4' />
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent>Cancel Rename</TooltipContent>
                    </Tooltip>
                  )}
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Button
                        variant='ghost'
                        size='icon'
                        onClick={handleDeleteChain}
                        disabled={renaming || !currentChainName}
                        className='h-9 w-9 text-destructive hover:text-destructive hover:bg-destructive/10'
                      >
                        <Trash2 className='h-4 w-4' />
                      </Button>
                    </TooltipTrigger>
                    <TooltipContent>Delete Chain</TooltipContent>
                  </Tooltip>
                </>
              )}
            </div>
          </TooltipProvider>
        </CardContent>
      </Card>

      <div className='flex-grow w-full h-[600px] border rounded-md relative overflow-hidden'>
        <Button
          onClick={handleAddStep}
          variant='outline'
          size='sm'
          className='absolute bottom-4 right-4 z-10 flex items-center shadow-md bg-background hover:bg-muted'
          disabled={isChainLoading || !chainData || !currentChainName || renaming}
        >
          <Plus className='mr-1 h-4 w-4' /> Add Step
        </Button>

        {!currentChainName ? (
          <div className='flex items-center justify-center h-full text-muted-foreground'>
            {!chainsData
              ? 'Loading chains...'
              : chainsData.length === 0
                ? 'No chains exist. Create one!'
                : 'Select a chain to view its steps.'}
          </div>
        ) : isChainLoading ? (
          <div className='absolute inset-0 flex items-center justify-center bg-background/50 z-20'>Loading chain...</div>
        ) : chainError ? (
          <div className='p-4 text-red-500'>Error loading chain data. Please try selecting it again.</div>
        ) : (
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            nodeTypes={nodeTypes}
            fitView
            fitViewOptions={{ padding: 0.2, duration: 300 }}
            className='bg-background'
            proOptions={{ hideAttribution: true }}
            minZoom={0.1}
            maxZoom={2}
            nodesDraggable={false}
            nodesConnectable={false}
            elementsSelectable={false}
            panOnDrag={true}
            panOnScroll={true}
            zoomOnScroll={true}
            zoomOnPinch={true}
            zoomOnDoubleClick={true}
            preventScrolling={false}
            nodesFocusable={false}
            selectionOnDrag={false}
          >
            <Controls className='react-flow__controls !bottom-auto !top-4 !left-4' />
            <Background />
          </ReactFlow>
        )}
      </div>

      <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create or Import Chain</DialogTitle>
          </DialogHeader>
          <div className='grid gap-4 py-4'>
            <div className='grid grid-cols-4 items-center gap-4'>
              <Label htmlFor='chain-name-dialog' className='text-right'>
                Name*
              </Label>
              <Input
                id='chain-name-dialog'
                value={newChainName}
                onChange={(e) => setNewChainName(e.target.value)}
                className='col-span-3'
                placeholder='Required for create/import'
              />
            </div>
            <div className='grid grid-cols-4 items-center gap-4'>
              <Label htmlFor='import-chain-dialog' className='text-right'>
                Import File
              </Label>
              <Input
                id='import-chain-dialog'
                type='file'
                accept='.json'
                onChange={handleChainImport}
                className='col-span-3 file:mr-2 file:rounded file:border file:border-solid file:border-input file:bg-background file:px-2 file:py-1 file:text-xs file:font-medium hover:file:bg-accent'
              />
            </div>
            <p className='text-xs text-muted-foreground col-span-4 text-center pt-2'>
              To Create: Enter name and click Create.
              <br />
              To Import: Select JSON file (name optional, defaults to filename).
            </p>
          </div>
          <DialogFooter>
            <Button
              variant='outline'
              onClick={() => {
                setShowCreateDialog(false);
                setNewChainName('');
              }}
            >
              Cancel
            </Button>
            <Button onClick={handleNewChain} disabled={!newChainName}>
              Create Chain
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

// Wrapper component
export default function ChainPageWrapper() {
  return (
    <SidebarPage title='Chains'>
      <ReactFlowProvider>
        <ChainFlow />
      </ReactFlowProvider>
    </SidebarPage>
  );
}
