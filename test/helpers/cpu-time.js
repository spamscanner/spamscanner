import process from 'node:process';

// The processor time this process has used, in milliseconds: for tests of how
// long work takes, as other work on a busy machine does not count toward it,
// as it does toward the time on a clock.
export function cpuTime() {
	const {user, system} = process.cpuUsage();
	return (user + system) / 1000;
}
