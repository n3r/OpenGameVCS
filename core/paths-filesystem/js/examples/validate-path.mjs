import { pathCollisionKeys } from '@opengamevcs/path-filesystem';

const result = pathCollisionKeys('Content/Characters/Hero.uasset', {
  caseMode: 'case-folded', profile: 'path.opengamevcs/portable@1',
});
process.stdout.write(`${JSON.stringify(result)}\n`);
