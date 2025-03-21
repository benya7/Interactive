import { chainMutations, createGraphQLClient } from '@/components/interactive/hooks/lib';
import '@/components/idiot/zod2gql/zod2gql';
import axios from 'axios';
import { getCookie } from 'cookies-next';
import useSWR, { SWRResponse } from 'swr';
import { z } from 'zod';

export const CompanySchema = z.object({
  agents: z.array(
    z.object({
      companyId: z.string().uuid(),
      default: z.boolean(),
      id: z.string().uuid(),
      name: z.string().min(1),
      status: z.union([z.boolean(), z.literal(null)]),
    }),
  ),
  id: z.string().uuid(),
  companyId: z.union([z.string().uuid(), z.null()]),
  name: z.string().min(1),
  primary: z.boolean(),
  roleId: z.number().int().positive(),
  // users: z.array(
  //   z.object({
  //     email: z.string().email(),
  //     firstName: z.string().min(1),
  //     id: z.string().uuid(),
  //     lastName: z.string().min(1),
  //   }),
  // ),
});

export type Company = z.infer<typeof CompanySchema>;
/**
 * Hook to fetch and manage company data
 * @returns SWR response containing array of companies
 */
export function useCompanies(): SWRResponse<Company[]> {
  const userHook = useUser();
  const { data: user } = userHook;

  const swrHook = useSWR<Company[]>(['/companies', user], () => user?.companies || [], { fallbackData: [] });

  const originalMutate = swrHook.mutate;
  swrHook.mutate = chainMutations(userHook, originalMutate);

  return swrHook;
}

/**
 * Hook to fetch and manage specific company data
 * @param id - Optional company ID to fetch
 * @returns SWR response containing company data or null
 */
export function useCompany(id?: string): SWRResponse<Company | null> {
  const companiesHook = useCompanies();
  const { data: companies } = companiesHook;
  const swrHook = useSWR<Company | null>(
    [`/company?id=${id}`, companies, getCookie('jwt')],
    async (): Promise<Company | null> => {
      if (!getCookie('jwt')) return null;
      try {
        if (id) {
          return companies?.find((c) => c.id === id) || null;
        } else {
          const agentName = getCookie('agixt-agent');
          const targetCompany =
            companies?.find((c) => (agentName ? c.agents.some((a) => a.name === agentName) : c.primary)) || null;
          if (!targetCompany) return null;
          targetCompany.extensions = (
            await axios.get(
              `${process.env.NEXT_PUBLIC_AGIXT_SERVER}/v1/companies/${targetCompany.id}/extensions`,

              {
                headers: {
                  Authorization: getCookie('jwt'),
                },
              },
            )
          ).data.extensions;
          return targetCompany;
        }
      } catch (error) {
        console.error('Error fetching company:', error);
        return null;
      }
    },
    { fallbackData: null },
  );

  const originalMutate = swrHook.mutate;
  swrHook.mutate = chainMutations(companiesHook, originalMutate);

  return swrHook;
}

export const RoleSchema = z.enum(['user', 'system', 'assistant', 'function']);

export const UserSchema = z.object({
  companies: z.array(CompanySchema),
  email: z.string().email(),
  firstName: z.string().min(1),
  id: z.string().uuid(),
  lastName: z.string().min(1),
});

export type User = z.infer<typeof UserSchema>;

/**
 * Hook to fetch and manage current user data
 * @returns SWR response containing user data
 */
export function useUser(): SWRResponse<User | null> {
  const client = createGraphQLClient();

  return useSWR<User | null>(
    ['/user', getCookie('jwt')],
    async (): Promise<User | null> => {
      if (!getCookie('jwt')) return null;
      try {
        const query = UserSchema.toGQL('query', 'GetUser');
        const response = await client.request<{ user: User }>(query);
        return UserSchema.parse(response.user);
      } catch (error) {
        console.error('Error fetching user:', error);
        return {
          companies: [],
          email: '',
          firstName: '',
          id: '',
          lastName: '',
        };
      }
    },
    {
      fallbackData: {
        companies: [],
        email: '',
        firstName: '',
        id: '',
        lastName: '',
      },
    },
  );
}
