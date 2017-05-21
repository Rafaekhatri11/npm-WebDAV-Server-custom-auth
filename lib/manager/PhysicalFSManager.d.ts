import { SerializedObject } from './ISerializer';
import { IResource, ResourceType } from '../resource/IResource';
import { FSManager } from './FSManager';
export declare class PhysicalFSManager implements FSManager {
    uid: string;
    serialize(resource: any, obj: SerializedObject): object;
    unserialize(data: any, obj: SerializedObject): IResource;
    newResource(fullPath: string, name: string, type: ResourceType, parent: IResource): IResource;
}
